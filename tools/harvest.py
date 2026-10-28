#!/usr/bin/env python3
"""Shuttle VPN harvester — pulls the node catalogue, decrypts it and every per-node
password, then writes ready-to-use OpenVPN configs.

Two crypto backends:

  (default) static  — pure Python, no device. The DES/AES constants live in
                      tools/powercrypto.py (recovered by emulating the obfuscated
                      builders in libpowervpn.so).
  --device          — Frida RPC bridge inside the running app. Only needed if the
                      app ever changes its package name or crypto layer.
                      Requires a rooted device, frida-server 16.x and `frida==16.5.9`
                      (frida 17 dropped the builtin Java bridge).

Examples
  python3 tools/harvest.py --out output                       # live API only
  python3 tools/harvest.py --out output --assets <apk>/assets # + bundled catalogue
  python3 tools/harvest.py --out output --device --assets <apk>/assets
"""
import argparse
import json
import os
import random
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import powercrypto as pc  # noqa: E402

PKG = "com.shuttlevpn.free.proxy.gaming"
BASES = ["https://api.fastcloud.me", "https://api.pm-img.com", "https://api.itranslator.info",
         "https://api.supershell.me", "http://193.108.117.109", "http://193.108.118.25"]
UA = ("Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/106.0.5249.126 Mobile Safari/537.36")


# ---------------------------------------------------------------- crypto backends
class StaticCrypto:
    name = "static (DES + AES constants from libpowervpn.so)"

    def enc(self, plain):
        return pc.des_encrypt(plain, pc.PREFIX_INIT)

    def dec(self, cipher):
        return pc.des_decrypt(cipher)

    def decb(self, cipher):
        return pc.aes_decrypt(cipher)


class DeviceCrypto:
    name = "device (frida bridge)"

    def __init__(self, port=27050):
        import subprocess
        env = dict(os.environ, MSYS_NO_PATHCONV="1")

        def adb(c):
            return subprocess.run(["adb", "shell", c], capture_output=True, text=True,
                                  env=env, timeout=60)

        adb("killall -9 fs1659 fs17 2>/dev/null; sleep 1")
        adb(f"setsid /data/local/tmp/fs1659 -l 0.0.0.0:{port} >/data/local/tmp/f16.log 2>&1 &")
        time.sleep(5)
        subprocess.run(["adb", "forward", f"tcp:{port}", f"tcp:{port}"], capture_output=True)
        pid = adb(f"pidof {PKG}").stdout.strip().split()
        for _ in range(3):
            if pid:
                break
            adb(f"pm enable {PKG}")
            adb(f"monkey -p {PKG} -c android.intent.category.LAUNCHER 1")
            time.sleep(10)
            pid = adb(f"pidof {PKG}").stdout.strip().split()
        if not pid:
            sys.exit("app is not running (launch it manually, then retry)")
        import frida
        dev = frida.get_device_manager().add_remote_device(f"127.0.0.1:{port}")
        sess = dev.attach(int(pid[0]))
        sc = sess.create_script(open(os.path.join(HERE, "rpc_bridge.js"), encoding="utf-8").read())
        sc.on("message", lambda m, d: print("MSG", m))
        sc.load()
        self.ex = sc.exports_sync
        print("bridge:", self.ex.init())

    def enc(self, plain):
        return self.ex.enc(plain)

    def dec(self, cipher):
        return self.ex.dec(cipher)

    def decb(self, cipher):
        return self.ex.decb(cipher)


# ---------------------------------------------------------------- network helpers
# The gateways are Cloudflare-fronted and publish AAAA records; on hosts without a
# working IPv6 route urllib hangs on the v6 attempt (curl falls back, urllib does not).
_orig_getaddrinfo = socket.getaddrinfo


def _ipv4_only(*args, **kwargs):
    return [r for r in _orig_getaddrinfo(*args, **kwargs) if r[0] == socket.AF_INET]


socket.getaddrinfo = _ipv4_only


def http_get(url, timeout=25, proxy=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                              "Content-Type": "application/x-www-form-urlencoded",
                                              "Accept-Language": "en-GB, en", "Accept": "*/*"})
    if proxy is None:
        proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or                 os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    proxy = proxy if proxy else ""
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {}))
    with opener.open(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "replace")


def query_string():
    uuid = "".join(random.choice("0123456789abcdef") for _ in range(32))
    return ("&lang=en&region=US&ver=234&pk=com.supervpn.vpn.free.proxy&uuid=" + uuid +
            "&country=US&sdk=30&isp=vodafone&operator=vodafone&network_type=5G"
            "&firstInstallTime=1700000000000")


def as_json(text):
    t = text.strip()
    if t.startswith("{") or t.startswith("["):
        return json.loads(t)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="output")
    ap.add_argument("--assets", default=None,
                    help="unpacked APK assets dir (adds the bundled catalogue + ovpn template)")
    ap.add_argument("--device", action="store_true", help="use the frida bridge instead of static crypto")
    ap.add_argument("--port", type=int, default=27050)
    ap.add_argument("--no-live", action="store_true", help="skip the API fetch")
    ap.add_argument("--base", default=None, help="force one gateway, e.g. https://api.fastcloud.me")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--proxy", default=None,
                    help="HTTP(S) proxy for the gateway call; defaults to $HTTPS_PROXY, "
                         "use --proxy '' to force a direct connection")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    cr = DeviceCrypto(a.port) if a.device else StaticCrypto()
    print("crypto backend:", cr.name)

    cfgs = {}
    template = None

    if a.assets:
        pp = open(os.path.join(a.assets, "privacy_policy.txt"), encoding="utf-8").read().strip()
        template = cr.decb(pp)
        if "client" not in template:
            sys.exit("template decryption failed")
        open(os.path.join(a.out, "ovpn_template.ovpn"), "w", encoding="utf-8",
             newline="\n").write(template)
        print(f"template ok ({len(template)} bytes)")

        usage = open(os.path.join(a.assets, "usage_policy.txt"), encoding="utf-8").read().strip()
        cfgs["bundled"] = json.loads(cr.dec(usage))
        print("bundled catalogue:", {k: len(cfgs["bundled"].get(k) or []) for k in
                                     ("servers", "vip_servers", "stream_servers")})
    else:
        tp = os.path.join(a.out, "ovpn_template.ovpn")
        if os.path.exists(tp):
            template = open(tp, encoding="utf-8").read()
        else:
            sys.exit("need --assets once to extract the OpenVPN template (or keep it in output/)")

    if not a.no_live:
        enc = cr.enc(query_string())
        for base in ([a.base] if a.base else BASES):
            url = base + "/superwg.php?v=" + urllib.parse.quote(enc, safe="")
            try:
                st, body = http_get(url, timeout=a.timeout, proxy=a.proxy)
            except Exception as e:
                print(f"[{base}] {e}")
                continue
            cfg = as_json(body)
            if cfg is None:
                for fn in (cr.dec, cr.decb):
                    try:
                        cfg = as_json(fn(body))
                    except Exception:
                        cfg = None
                    if cfg:
                        break
            if not cfg:
                print(f"[{base}] HTTP {st} len={len(body)} — unusable")
                continue
            cfgs["live"] = cfg
            print(f"live catalogue from {base}: {len(cfg.get('servers') or [])} servers, "
                  f"{len(cfg.get('vip_servers') or [])} vip")
            break
        if "live" not in cfgs:
            print("[!] no live source reachable, continuing with the bundled catalogue only")

    nodes, seen = [], set()
    for src, cfg in cfgs.items():
        for group in ("servers", "vip_servers", "stream_servers"):
            for srv in cfg.get(group) or []:
                host = srv.get("host")
                if not host or host in seen:
                    continue
                pw = None
                if srv.get("enpass"):
                    try:
                        pw = cr.decb(srv["enpass"])
                    except Exception as e:
                        print("  decrypt failed:", host, e)
                if not pw:
                    continue
                seen.add(host)
                nodes.append({"source": src, "group": group, "server_id": srv.get("server_id"),
                              "country": srv.get("country"),
                              "name": srv.get("alisa_name") or srv.get("country_name"),
                              "host": host, "user": "superike", "pass": pw,
                              "ports": {"udp": (cfg.get("udp") or [800])[0],
                                        "tcp": (cfg.get("tcp") or [8080])[0]},
                              "load": srv.get("load")})
    print(f"nodes with credentials: {len(nodes)} (unique hosts)")

    creddir = os.path.join(a.out, "creds")
    cfgdir = os.path.join(a.out, "cfg")
    os.makedirs(creddir, exist_ok=True)
    os.makedirs(cfgdir, exist_ok=True)
    tpl_body = template.replace("auth-user-pass", "auth-user-pass __CREDS__", 1)
    for n in nodes:
        open(os.path.join(creddir, n["host"] + ".txt"), "w", newline="\n").write(
            n["user"] + "\n" + n["pass"] + "\n")
        # relative on purpose: openvpn resolves it against its own CWD (see pool_layer.py)
        tpl = tpl_body.replace("__CREDS__", "creds/" + n["host"] + ".txt")
        for proto, port in n["ports"].items():
            body = tpl.replace("client\n", f"client\nremote {n['host']} {port} {proto}\n", 1)
            open(os.path.join(cfgdir, f"{n['host']}_{proto}.ovpn"), "w", newline="\n").write(body)
    json.dump(nodes, open(os.path.join(a.out, "nodes.json"), "w", encoding="utf-8"),
              indent=1, ensure_ascii=False)
    print(f"wrote {len(nodes)} nodes -> {a.out}/nodes.json + cfg/ + creds/")


if __name__ == "__main__":
    main()

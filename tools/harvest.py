#!/usr/bin/env python3
"""Shuttle VPN harvester.

Pulls the live node catalogue, decrypts it and every per-node password through a
Frida crypto bridge running inside the app, then writes ready-to-use OpenVPN
configs.

Prerequisites
  * rooted emulator/device with the app installed and frida-server 16.x running
    (`frida == 16.5.9` client; frida 17 dropped the builtin Java bridge)
  * `adb forward tcp:27050 tcp:27050`
  * the APK unpacked somewhere: pass --assets <dir with privacy_policy.txt>

  python3 harvest.py --assets ../raw/assets --out ../output
"""
import argparse
import json
import os
import random
import re
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request

PKG = "com.shuttlevpn.free.proxy.gaming"
BASES = ["https://api.fastcloud.me", "https://api.pm-img.com", "https://api.itranslator.info",
         "https://api.supershell.me", "http://193.108.117.109", "http://193.108.118.25"]
UA = ("Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/106.0.5249.126 Mobile Safari/537.36")


def adb(cmd, t=60):
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    return subprocess.run(["adb", "shell", cmd], capture_output=True, text=True, env=env, timeout=t)


def bridge(port, tries=10):
    import frida
    pid = adb(f"pidof {PKG}").stdout.strip().split()
    for attempt in range(3):
        if pid:
            break
        adb(f"pm enable {PKG}")            # emulator/Play-Protect sometimes disables it
        adb(f"monkey -p {PKG} -c android.intent.category.LAUNCHER 1")
        time.sleep(10)
        pid = adb(f"pidof {PKG}").stdout.strip().split()
        print(f"launch attempt {attempt + 1}: pid={pid}")
    if not pid:
        sys.exit("app is not running (try `adb shell am start -n <pkg>/<activity>` manually)")
    dev = frida.get_device_manager().add_remote_device(f"127.0.0.1:{port}")
    sess = None
    for _ in range(tries):
        try:
            sess = dev.attach(int(pid[0]))
            break
        except Exception as e:
            print("attach retry:", e)
            time.sleep(3)
    if sess is None:
        sys.exit("cannot attach (check frida-server version == python frida version)")
    sc = sess.create_script(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                              "rpc_bridge.js"), encoding="utf-8").read())
    sc.on("message", lambda m, d: print("MSG", m))
    sc.load()
    ex = sc.exports_sync
    print("bridge:", ex.init())
    return sess, ex


def http_get(url, timeout=25):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                              "Content-Type": "application/x-www-form-urlencoded",
                                              "Accept-Language": "en-GB, en", "Accept": "*/*"})
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                         urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "replace")


def query_string():
    uuid = "".join(random.choice("0123456789abcdef") for _ in range(32))
    return ("&lang=en&region=US&ver=234&pk=com.supervpn.vpn.free.proxy&uuid=" + uuid +
            "&country=US&sdk=30&isp=vodafone&operator=vodafone&network_type=5G"
            "&firstInstallTime=1700000000000")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=27050)
    ap.add_argument("--assets", required=True, help="dir containing privacy_policy.txt")
    ap.add_argument("--out", default="output")
    ap.add_argument("--no-live", action="store_true", help="skip the API fetch, bundled config only")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    sess, ex = bridge(a.port)

    # 1) OpenVPN template (ca + tls-crypt) lives encrypted in the assets
    pp = open(os.path.join(a.assets, "privacy_policy.txt"), encoding="utf-8").read().strip()
    template = ex.decb(pp)
    if "client" not in template:
        sys.exit("template decryption failed")
    open(os.path.join(a.out, "ovpn_template.ovpn"), "w", encoding="utf-8").write(template)
    print(f"template ok ({len(template)} bytes)")

    cfgs = {}

    # 2) bundled catalogue
    usage = open(os.path.join(a.assets, "usage_policy.txt"), encoding="utf-8").read().strip()
    bundled = json.loads(ex.dec(usage))
    cfgs["bundled"] = bundled
    print("bundled catalogue:", {k: len(bundled.get(k) or []) for k in
                                 ("servers", "vip_servers", "stream_servers")})

    # 3) live catalogue from the API
    if not a.no_live:
        enc = ex.enc(query_string())
        for base in BASES:
            url = base + "/superwg.php?v=" + urllib.parse.quote(enc, safe="")
            try:
                st, body = http_get(url)
            except Exception as e:
                print(f"[{base}] {e}")
                continue
            if st != 200 or len(body) < 200:
                print(f"[{base}] HTTP {st} len={len(body)}")
                continue
            for fn in (ex.dec, ex.decb):
                try:
                    cand = fn(body)
                except Exception:
                    continue
                if cand and cand.lstrip().startswith("{"):
                    cfgs["live"] = json.loads(cand)
                    print(f"live catalogue from {base}: "
                          f"{len(cfgs['live'].get('servers') or [])} servers")
                    break
            if "live" in cfgs:
                break

    # 4) credentials + per-node configs
    nodes = []
    for src, cfg in cfgs.items():
        for group in ("servers", "vip_servers", "stream_servers"):
            for srv in cfg.get(group) or []:
                pw = None
                err = None
                if srv.get("enpass"):
                    for fn in (ex.decb, ex.dec):
                        try:
                            pw = fn(srv["enpass"])
                        except Exception as e:
                            err = e
                            pw = None
                        if pw:
                            break
                if not pw:
                    if err is not None:
                        print("  decrypt failed:", type(err).__name__, err)
                    continue
                nodes.append({"source": src, "group": group, "server_id": srv.get("server_id"),
                              "country": srv.get("country"),
                              "name": srv.get("alisa_name") or srv.get("country_name"),
                              "host": srv.get("host"), "user": "superike", "pass": pw,
                              "ports": {"udp": (cfg.get("udp") or [800])[0],
                                        "tcp": (cfg.get("tcp") or [8080])[0]},
                              "load": srv.get("load")})
    uniq = {}
    for n in nodes:
        uniq.setdefault(n["host"], n)
    nodes = list(uniq.values())
    print(f"nodes with credentials: {len(nodes)} (unique hosts)")

    creddir = os.path.join(a.out, "creds")
    cfgdir = os.path.join(a.out, "cfg")
    os.makedirs(creddir, exist_ok=True)
    os.makedirs(cfgdir, exist_ok=True)
    body_tpl = template.replace("auth-user-pass", "auth-user-pass " +
                                os.path.abspath(os.path.join(creddir, "X.txt")))
    for n in nodes:
        open(os.path.join(creddir, n["host"] + ".txt"), "w", newline="\n").write(
            n["user"] + "\n" + n["pass"] + "\n")
        tpl = body_tpl.replace(os.path.join(creddir, "X.txt"),
                               os.path.join(creddir, n["host"] + ".txt"))
        for proto, port in n["ports"].items():
            body = tpl.replace("client\n", f"client\nremote {n['host']} {port} {proto}\n", 1)
            open(os.path.join(cfgdir, f"{n['host']}_{proto}.ovpn"), "w", newline="\n").write(body)
    json.dump(nodes, open(os.path.join(a.out, "nodes.json"), "w"), indent=1, ensure_ascii=False)
    print(f"wrote {len(nodes)} nodes -> {a.out}/nodes.json + cfg/ + creds/")


if __name__ == "__main__":
    main()

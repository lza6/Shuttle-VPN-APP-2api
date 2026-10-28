#!/usr/bin/env python3
"""Shuttle VPN -> SOCKS5 pool layer (Linux/WSL, one netns per node).

Topology per node i:
  host/WSL 0.0.0.0:44000+i  --TCP relay-->  10.200.x.y:34000+i  (microsocks, inside netns vpnI)
                                            -> tun0 (OpenVPN) -> node

Fail-closed: inside the netns, any egress on the veth that is NOT the VPN server /32
is dropped by iptables, so a dropped tunnel can never leak the host's real IP.

Usage:
  python3 pool_layer.py up nodes.json [--max N]
  python3 pool_layer.py status
  python3 pool_layer.py down
"""
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

STATE = "/tmp/shuttle_pool_state.json"
BASE_RELAY = 44000
BASE_SOCKS = 34000
TUNNEL_RESOLV = "/tmp/shuttle_pool_resolv.conf"


def sh(cmd, timeout=60):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)


def log(*a):
    print(*a, flush=True)


def lab(idx):
    base = idx * 4
    return f"10.200.{base // 250}.{base % 250 + 1}", f"10.200.{base // 250}.{base % 250 + 2}"


def setup_host():
    sh("sysctl -qw net.ipv4.ip_forward=1")
    sh("iptables -t nat -C POSTROUTING -s 10.200.0.0/16 -j MASQUERADE 2>/dev/null || "
       "iptables -t nat -A POSTROUTING -s 10.200.0.0/16 -j MASQUERADE")
    sh("iptables -C FORWARD -s 10.200.0.0/16 -j ACCEPT 2>/dev/null || "
       "iptables -I FORWARD 1 -s 10.200.0.0/16 -j ACCEPT")
    sh("iptables -C FORWARD -d 10.200.0.0/16 -j ACCEPT 2>/dev/null || "
       "iptables -I FORWARD 1 -d 10.200.0.0/16 -j ACCEPT")
    with open(TUNNEL_RESOLV, "w") as f:
        f.write("nameserver 8.8.8.8\nnameserver 8.8.4.4\n")


def teardown(idx):
    sh(f"ip netns del vpn{idx} 2>/dev/null; ip link del veth{idx} 2>/dev/null")


def wait_handshake(logf, secs=35):
    for _ in range(secs):
        time.sleep(1)
        try:
            if "Initialization Sequence Completed" in open(logf, errors="ignore").read():
                return True
        except FileNotFoundError:
            pass
    return False


def run_node(idx, node, cfg_path):
    host, port, proto = node["host"], node["port"], node["proto"]
    hnet, cnet = lab(idx)
    ns, veth = f"vpn{idx}", f"veth{idx}"
    logf = f"/tmp/ovpn.{idx}.log"

    teardown(idx)
    if sh(f"ip netns add {ns}").returncode:
        return None
    sh(f"ip link add {veth} type veth peer name {veth}p")
    sh(f"ip link set {veth}p netns {ns}")
    sh(f"ip addr add {hnet}/30 dev {veth}")
    sh(f"ip link set {veth} up")
    sh(f"ip netns exec {ns} ip link set lo up")
    sh(f"ip netns exec {ns} ip addr add {cnet}/30 dev {veth}p")
    sh(f"ip netns exec {ns} ip link set {veth}p up")
    sh(f"ip netns exec {ns} ip route add default via {hnet}")
    open(logf, "w").close()

    subprocess.Popen(
        f"ip netns exec {ns} openvpn --config {cfg_path} --dev tun0 --verb 3 --auth-nocache "
        f"--log {logf} --writepid /tmp/ovpn.{idx}.pid",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if not wait_handshake(logf):
        log(f"[{idx}] FAIL handshake {host}:{port}/{proto}")
        teardown(idx)
        return None

    # fail-closed guard: the veth may only carry traffic to the VPN server or back to the host
    sh(f"ip netns exec {ns} iptables -A OUTPUT -o {veth}p ! -d {host}/32 ! -d {hnet}/32 -j DROP")
    log(f"[{idx}] tunnel up {host}:{port}/{proto}")
    return {"ns": ns, "veth": veth, "hnet": hnet, "cnet": cnet, "logf": logf, "host": host}


def start_socks(idx):
    cnet = lab(idx)[1]
    port = BASE_SOCKS + idx
    sh(f"ip netns exec vpn{idx} unshare -m --propagation private sh -c "
       f"'mount --bind {TUNNEL_RESOLV} /etc/resolv.conf && exec microsocks -i 0.0.0.0 -p {port}' "
       f"> /tmp/socks.{idx}.log 2>&1 &")
    return cnet, port


def relay(local_port, target_host, target_port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", local_port))
    srv.listen(128)

    def pump(a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except Exception:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    s.close()
                except Exception:
                    pass

    def handle(cli):
        try:
            up = socket.create_connection((target_host, target_port), 10)
        except Exception:
            cli.close()
            return
        threading.Thread(target=pump, args=(cli, up), daemon=True).start()
        threading.Thread(target=pump, args=(up, cli), daemon=True).start()

    def loop():
        while True:
            try:
                cli, _ = srv.accept()
            except Exception:
                return
            threading.Thread(target=handle, args=(cli,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


def probe(idx):
    """exit IP + latency through the tunnel (ipify: no rate limit, plain text)"""
    t0 = time.time()
    out = sh(f"ip netns exec vpn{idx} unshare -m --propagation private sh -c "
             f"'mount --bind {TUNNEL_RESOLV} /etc/resolv.conf; curl -s -m 15 https://api.ipify.org'").stdout.strip()
    ms = int((time.time() - t0) * 1000)
    ip = out.strip()
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip or ""):
        try:
            ip = json.loads(out).get("ip")
        except Exception:
            return None
    if not ip:
        return None
    return {"ip": ip, "ms": ms}


def watchdog(state):
    while True:
        time.sleep(30)
        for s in state:
            r = probe(s["idx"])
            if r:
                s["exit"] = r
                s["fail"] = 0
            else:
                s["fail"] = s.get("fail", 0) + 1
        try:
            json.dump(state, open(STATE, "w"), indent=1)
        except Exception:
            pass


def cmd_up(nodes_file, maxn):
    setup_host()
    nodes = json.load(open(nodes_file))[:maxn]
    state = []
    for i, n in enumerate(nodes):
        r = run_node(i, n, n["cfg"])
        if not r:
            continue
        cnet, sport = start_socks(i)
        relay(BASE_RELAY + i, cnet, sport)
        ex = probe(i)
        rec = {"idx": i, "host": n["host"], "port": n["port"], "proto": n["proto"],
               "country": n.get("country"), "name": n.get("name"),
               "socks": f"socks5://127.0.0.1:{BASE_RELAY + i}", "exit": ex, "fail": 0,
               "ns": r["ns"], "hnet": r["hnet"], "cnet": cnet, "sport": sport}
        state.append(rec)
        log(f"[{i}] {n['host']}:{n['port']}/{n['proto']} -> {ex}")
    json.dump(state, open(STATE, "w"), indent=1)
    threading.Thread(target=watchdog, args=(state,), daemon=True).start()
    log(f"pool up: {len(state)}/{len(nodes)} nodes, state={STATE}")
    while True:
        time.sleep(3600)


def cmd_down(upto=64):
    for i in range(upto):
        teardown(i)
    sh(f"pkill -f 'microsocks -i 0.0.0.0 -p {BASE_SOCKS}' 2>/dev/null")
    log("torn down")


def cmd_status():
    if not os.path.exists(STATE):
        log("no state")
        return
    for s in json.load(open(STATE)):
        log(f"{s['idx']:>2} {s['host']:>16}:{s['port']}/{s['proto']:<3} {s['socks']} "
            f"exit={s['exit']} fail={s.get('fail', 0)} {s['country']} {s['name']}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "up":
        m = 64
        if "--max" in sys.argv:
            m = int(sys.argv[sys.argv.index("--max") + 1])
        cmd_up(sys.argv[2], m)
    elif cmd == "down":
        cmd_down()
    else:
        cmd_status()

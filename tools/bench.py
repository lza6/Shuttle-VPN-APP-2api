#!/usr/bin/env python3
"""SOCKS5 stress/bench for the Shuttle VPN pool.

  python3 bench.py --ports 44000-44009 --conc 4 --rounds 3

Metrics per endpoint: success rate, latency P50/P95, median throughput (Mbps),
and the exit IP seen on the far side (must differ from the host's own IP).
"""
import argparse
import json
import socket
import ssl
import statistics
import struct
import sys
import threading
import time
import urllib.request

IP_CHECK = ("api.ipify.org", 443, "/")
SPEED = ("speed.cloudflare.com", 443, "/__down?bytes=2000000")


def socks5_open(proxy_host, proxy_port, dst_host, dst_port, timeout=15):
    s = socket.create_connection((proxy_host, proxy_port), timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise OSError("socks5 auth reject")
    h = dst_host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", dst_port))
    rep = s.recv(4)
    if len(rep) < 2 or rep[1] != 0:
        raise OSError(f"socks5 connect failed {rep!r}")
    atyp = rep[3]
    if atyp == 1:
        s.recv(4)
    elif atyp == 3:
        n = s.recv(1)[0]
        s.recv(n)
    elif atyp == 4:
        s.recv(16)
    s.recv(2)
    return s


def http_get(port, host, dport, path, tls=False, timeout=20):
    t0 = time.time()
    s = socks5_open("127.0.0.1", port, host, dport, timeout)
    try:
        if tls:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=host)
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: bench/1\r\n\r\n"
        s.sendall(req.encode())
        buf = b""
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
    finally:
        try:
            s.close()
        except Exception:
            pass
    dt = time.time() - t0
    head, _, body = buf.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1]) if head.startswith(b"HTTP/") else 0
    return status, body, dt


def host_ip():
    try:
        req = urllib.request.Request("http://ip-api.com/json?fields=query",
                                     headers={"User-Agent": "bench/1"})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=10) as r:
            return json.loads(r.read()).get("query")
    except Exception:
        return None


def bench_port(port, rounds, conc):
    lat, ok, fail, ip, cc, isp, mbps = [], 0, 0, None, None, None, []
    lock = threading.Lock()

    def one():
        nonlocal ok, fail, ip
        try:
            st, body, dt = http_get(port, *IP_CHECK, tls=True)
            txt = body.decode(errors="ignore").strip()
            if st == 200 and txt.count(".") == 3 and len(txt) < 24 and "," not in txt:
                with lock:
                    ok += 1
                    lat.append(dt)
                    ip = txt
                return
            with lock:
                fail += 1
        except Exception:
            with lock:
                fail += 1

    for _ in range(rounds):
        ths = [threading.Thread(target=one) for _ in range(conc)]
        [t.start() for t in ths]
        [t.join() for t in ths]

    # one throughput sample
    try:
        st, body, dt = http_get(port, *SPEED, tls=True, timeout=40)
        if st in (200, 206) and dt > 0:
            mbps.append(len(body) * 8 / dt / 1e6)
    except Exception:
        pass

    total = ok + fail
    return {
        "port": port,
        "ok": ok, "fail": fail,
        "success_rate": round(ok / total * 100, 1) if total else 0.0,
        "p50_ms": round(statistics.median(lat) * 1000) if lat else None,
        "p95_ms": round(sorted(lat)[int(len(lat) * 0.95) - 1] * 1000) if len(lat) >= 2 else None,
        "max_ms": round(max(lat) * 1000) if lat else None,
        "mbps": round(max(mbps), 2) if mbps else None,
        "exit_ip": ip, "cc": cc, "isp": isp,
    }


def parse_ports(spec):
    out = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            out += list(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--ports", default="44000-44009")
    ap.add_argument("--conc", type=int, default=4)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--json", default="/tmp/bench_result.json")
    a = ap.parse_args()

    own = host_ip()
    print(f"host exit ip = {own}", flush=True)
    res = []
    for p in parse_ports(a.ports):
        r = bench_port(p, a.rounds, a.conc)
        r["host_ip"] = own
        r["tunnel_ok"] = bool(r["exit_ip"] and own and r["exit_ip"] != own)
        res.append(r)
        print(json.dumps(r, ensure_ascii=False), flush=True)
    json.dump(res, open(a.json, "w"), indent=1, ensure_ascii=False)
    alive = [r for r in res if r["success_rate"] > 0 and r["tunnel_ok"]]
    print(f"\n== summary: {len(alive)}/{len(res)} endpoints OK through tunnel, "
          f"median p50={statistics.median([r['p50_ms'] for r in alive]) if alive else '-'}ms ==")

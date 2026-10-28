#!/usr/bin/env python3
"""Shuttle VPN pool demo — run inside WSL where the tunnels live.

  python3 demo/server.py            # http://127.0.0.1:8920

Endpoints
  GET /                dashboard
  GET /api/pool        pool state + cached exit-IP probe per node
  GET /api/probe?port= live probe through one SOCKS5 endpoint
  GET /api/bench?conc=2&rounds=2   stress the whole pool (SOCKS5, real traffic)
  GET /api/nodes       sanitized node table (host/country only, no credentials)
"""
import json
import os
import statistics
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, HERE)

from concurrent.futures import ThreadPoolExecutor, wait as fut_wait
import bench as benchmod  # noqa: E402

STATE = "/tmp/shuttle_pool_state.json"
CACHE = {"ts": 0, "data": None}
LOCK = threading.Lock()


def load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return []


def probe_one(s):
    try:
        r = benchmod.bench_port(44000 + s["idx"], 1, 1)
    except Exception:
        r = {"success_rate": 0.0, "p50_ms": None, "exit_ip": None, "mbps": None}
    return {**s, "live": r}


DEAD = {"success_rate": 0.0, "p50_ms": None, "exit_ip": None, "mbps": None}


def probe_all(force=False, budget=14):
    with LOCK:
        if not force and time.time() - CACHE["ts"] < 25 and CACHE["data"]:
            return CACHE["data"]
        state = load_state()
        ex = ThreadPoolExecutor(max_workers=max(1, len(state)))
        futs = {ex.submit(probe_one, s): s for s in state}
        done, pending = fut_wait(futs, timeout=budget)
        out = []
        for f, s in futs.items():
            if f in done:
                out.append(f.result())
            else:
                out.append({**s, "live": dict(DEAD)})
        ex.shutdown(wait=False)
        out.sort(key=lambda x: x["idx"])
        CACHE.update(ts=time.time(), data=out)
        return out


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            p = os.path.join(HERE, "index.html")
            return self._send(200, open(p, "rb").read(), "text/html; charset=utf-8")
        if u.path == "/api/pool":
            return self._send(200, probe_all(force=q.get("force") == ["1"]))
        if u.path == "/api/probe":
            port = int(q.get("port", ["44000"])[0])
            return self._send(200, benchmod.bench_port(port, 1, 1))
        if u.path == "/api/bench":
            conc = int(q.get("conc", ["2"])[0])
            rounds = int(q.get("rounds", ["2"])[0])
            res = []
            for s in load_state():
                r = benchmod.bench_port(44000 + s["idx"], rounds, conc)
                r.update(host=s["host"], port_name=s["port"], proto=s["proto"])
                res.append(r)
            ok = [r for r in res if r["success_rate"] > 0]
            summary = {
                "endpoints": len(res), "alive": len(ok),
                "p50_median_ms": statistics.median([r["p50_ms"] for r in ok if r["p50_ms"]]) if ok else None,
                "success_rate_avg": round(statistics.mean([r["success_rate"] for r in res]), 1) if res else 0,
                "mbps_median": statistics.median([r["mbps"] for r in res if r["mbps"]]) if any(r["mbps"] for r in res) else None,
            }
            return self._send(200, {"summary": summary, "results": res})
        if u.path == "/api/nodes":
            p = os.path.join(ROOT, "samples", "nodes.public.json")
            if os.path.exists(p):
                return self._send(200, json.load(open(p)))
            return self._send(200, [{"host": s["host"], "country": s["country"]} for s in load_state()])
        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8920
    print(f"demo on http://0.0.0.0:{port}  (state={STATE})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()

#!/usr/bin/env python3
"""Emit a new-api proxy list from the running pool.

new-api (relay/channel/tryingopen) reads TRYINGOPEN_PROXY_FILE: comma separated
list of files, one `socks5://host:port` per line, `#` starts a comment.
Entries from that file are loaded as source="residential" with healthScore 1.0.

  python3 gen_newapi_pool.py --host 172.17.0.1 --out /opt/new-api/proxies/shuttle.txt
"""
import argparse
import json
import os

STATE = "/tmp/shuttle_pool_state.json"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", default=STATE)
    ap.add_argument("--host", default="127.0.0.1",
                    help="host the new-api process can reach the relays on "
                         "(127.0.0.1 same box, 172.17.0.1 docker bridge, host.docker.internal)")
    ap.add_argument("--base", type=int, default=44000)
    ap.add_argument("--out", default="-")
    args = ap.parse_args()

    if not os.path.exists(args.state):
        raise SystemExit(f"pool state not found: {args.state} (run `pool_layer.py up` first)")
    state = json.load(open(args.state))
    lines = ["# Shuttle VPN pool — generated %s" % __import__("datetime").datetime.now().isoformat(timespec="seconds"),
             "# one tunnel = one entry; keep this file in sync with pool_layer.py up"]
    n = 0
    for s in state:
        if s.get("exit") is None and s.get("fail", 0) >= 1:
            continue
        lines.append(f"socks5://{args.host}:{args.base + s['idx']}  # {s['host']}:{s['port']}/{s['proto']} "
                     f"{s.get('country') or ''} {s.get('exit', {}).get('ip') if s.get('exit') else ''}")
        n += 1
    text = "\n".join(lines) + "\n"
    if args.out == "-":
        print(text)
    else:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        open(args.out, "w").write(text)
        print(f"{n} proxies -> {args.out}")


if __name__ == "__main__":
    main()

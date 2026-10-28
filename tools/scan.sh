#!/bin/bash
# OpenVPN liveness sweep over output/cfg/*.ovpn — handshake-only, no tun.
# usage: bash tools/scan.sh [parallel] [connect_timeout] [poll_timeout]
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
CFGDIR="${CFGDIR:-$ROOT/output/cfg}"
LOGDIR="${LOGDIR:-$ROOT/output/logs}"
PAR="${1:-12}"; CT="${2:-8}"; PT="${3:-25}"
mkdir -p "$LOGDIR"

run_one() {
  local f="$1" base
  base=$(basename "$f" .ovpn)
  timeout $((PT + 10)) openvpn --config "$f" --dev null --ifconfig-noexec --route-noexec \
    --connect-retry-max 1 --connect-timeout "$CT" --server-poll-timeout "$PT" \
    --verb 3 --auth-nocache > "$LOGDIR/$base.log" 2>&1
  if grep -q "Initialization Sequence Completed" "$LOGDIR/$base.log"; then echo "UP      $base"
  elif grep -q "AUTH_FAILED" "$LOGDIR/$base.log"; then echo "AUTHFAIL $base"
  elif grep -q "TLS Error" "$LOGDIR/$base.log"; then echo "TLSERR  $base"
  else echo "DEAD    $base"
  fi
}
export -f run_one
export LOGDIR
ls "$CFGDIR"/*.ovpn | xargs -P "$PAR" -I{} bash -c 'run_one "$@"' _ {}

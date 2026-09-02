#!/usr/bin/env bash
# Usage: run_bench.sh <label> [duration] [workers]
# Starts the ASGI bench app, runs wrk against it, prints the wrk report.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LABEL="${1:?label required}"
DUR="${2:-15}"
WORKERS="${3:-1}"
PORT="${BENCH_PORT:-8123}"
PY="${PY:-$HERE/../.venv/bin/python}"

BENCH_WORKERS="$WORKERS" BENCH_PORT="$PORT" "$PY" "$HERE/asgi_app.py" >/tmp/freastal_bench_server.log 2>&1 &
SRV=$!
trap 'kill -9 $SRV 2>/dev/null; pkill -9 -f asgi_app.py 2>/dev/null' EXIT

for _ in $(seq 1 100); do
  if curl -sf -o /dev/null "http://127.0.0.1:$PORT/"; then break; fi
  sleep 0.1
done
if ! curl -sf -o /dev/null "http://127.0.0.1:$PORT/"; then
  echo "server failed to start"; cat /tmp/freastal_bench_server.log; exit 1
fi

wrk -t4 -c40 -d"${DUR}s" --latency "http://127.0.0.1:$PORT/" \
  | sed "s/^/[$LABEL] /"

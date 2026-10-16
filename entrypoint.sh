#!/bin/sh
# Start FalkorDB, build the graph if empty, then serve.
set -e

echo "[keystone] starting FalkorDB…"
redis-server --loadmodule /var/lib/falkordb/bin/falkordb.so \
             --daemonize no --save '' --appendonly no &
FALKOR_PID=$!

# Stop the container if FalkorDB dies: there is no degraded mode by design.
trap 'kill -TERM $FALKOR_PID 2>/dev/null; exit 0' TERM INT

echo "[keystone] building graph if needed…"
python -m keystone.scripts.bootstrap

echo "[keystone] serving on :${PORT}"
exec python -m uvicorn keystone.api.main:app --host 0.0.0.0 --port "${PORT}"

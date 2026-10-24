#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cleanup() {
  kill "$API_PID" "$UI_PID" 2>/dev/null || true
  wait "$API_PID" "$UI_PID" 2>/dev/null || true
}
(cd backend && exec .venv/bin/python -m uvicorn main:app --host 127.0.0.1 --port 8000 --no-access-log) &
API_PID=$!
npm run dev &
UI_PID=$!
trap cleanup EXIT INT TERM
wait -n "$API_PID" "$UI_PID"

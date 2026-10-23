#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
npm run lint
node_modules/.bin/tsx scripts/check-api.ts
npm run build
cd backend
PYTHON_BIN="${CODEGUARD_PYTHON:-.venv/bin/python}"
"$PYTHON_BIN" -m unittest discover -s feat_6_runtime -p 'test_*.py' -v
"$PYTHON_BIN" feat_5_evaluation/evaluate.py --output ../docs/reports/latest-evaluation.json

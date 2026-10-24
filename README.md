# Code Kavach

The repository root contains the React UI and CPU-only Python analyzer. No LLM key is required. Submitted source is inspected, never executed.

## Run locally

From this directory, start the backend:

```bash
cd backend
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

In a second terminal, from this directory:

```bash
npx --yes bun install
npm run dev
```

Open http://localhost:3000/app/scan. Vite proxies `/v1` and `/healthz` to port 8000. Live Python scanning is the default. If you previously saved mock mode in Settings, disable it and clear the API base URL to use the proxy. An optional browser demo engine remains available via Settings; its results are marked mock.

## Features

- Python AST analysis, bounded result cache, request identity, local audit events, and fail-closed parser handling.
- Live verdicts, measured timing, findings with source lines, detailed remediation examples, and score traces in JSON.
- Existing updated UI for scan history, exports, batch input, and analytics; scanner edits clear stale results.
- Public 42-sample evaluation in the Batch page, including per-category metrics and downloadable reports.

API: `POST /v1/guard` with `{"code":"..."}` returns the fixed schema; `?detail=full` adds findings and diagnostics. Also available: `/healthz`, `POST /v1/guard/batch`, and `POST /v1/evaluation`. Source limit is 64 KiB. Browser batch input currently scans items sequentially.

## Checks

```bash
npm run lint
node_modules/.bin/tsx scripts/check-api.ts
npm run build
cd backend
.venv/bin/python -m pip install httpx==0.28.1
.venv/bin/python -m unittest discover -s feat_6_runtime -p 'test_*.py' -v
.venv/bin/python feat_5_evaluation/evaluate.py --output /tmp/code-kavach-evaluation.json
```

The backend remains a local baseline with incomplete language and control-flow coverage. Unsupported inputs fail closed. Risk scores are deterministic severity scores, not calibrated probabilities. The UI interception simulation does not execute code or prove runtime enforcement. Public deployment controls and the controlled execution wrapper remain pending. See `context.md`, `prd.md`, and `breakdown.md` for the original requirements and planning history.

Core components: React, Vite and FastAPI (MIT), Lucide (ISC), Uvicorn and Starlette (BSD-3-Clause), Python AST (PSF). ApexCharts uses conditional community/commercial/OEM licensing; distribution eligibility has not been established. See [the licence register](docs/licenses.md) and installed dependency inventory. No pretrained model is used by the Python verdict path. Development used an AI coding assistant.

## Master prompt implementation

The [phase tracker](docs/implementation-plan.md) breaks down `master_prompt.md` and records pending gates. See [assumptions](docs/assumptions.md), [initial measured baseline](docs/reports/initial-evaluation.json), and [Phase 0 report](docs/reports/phase-0.md). The full master prompt is not implemented yet.

Run the checks together with `bash scripts/check-local.sh` after installing `backend/requirements-dev.txt`. The same commands are wired into `.github/workflows/check.yml`; a prepared workflow is not a hosted CI pass.

## Directory structure

- `src/`: React pages, components, API client, and browser utilities.
- `backend/`: FastAPI service, analyzer, findings, evaluation, and runtime tests.
- `scripts/`: API adapter checks.
- `context.md`, `prd.md`, `breakdown.md`, `frontend.md`: requirements and planning.
- `CodeGuard_Hackathon_Problem_Statement.docx`: original problem statement.
- `codeguard_dev.jsonl`: public evaluation dataset.
- `rough_images/`: design references used by the planning documents.

Run all frontend commands from the repository root. The legacy frontend and nested project copies have been removed. Dependencies and build output are ignored by Git.

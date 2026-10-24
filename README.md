# Code Kavach — CodeGuard

A real-time, CPU-only, **pre-execution** safety gate for LLM-generated code.
The agent wrapper sends the proposed code to CodeGuard; CodeGuard answers
`allow` or `block` in milliseconds with a risk score, categories, a reason and
the affected lines; the wrapper refuses to run anything blocked.

**No LLM is called anywhere in the verdict path.** Detection is deterministic
rules + Python AST/taint + lexical analyzers for bash, SQL, JavaScript, YAML and
Markdown. Submitted code is parsed, never executed. No network is used during a
scan.

## Run locally

```bash
# terminal 1 — API
cd backend
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m uvicorn main:app --host 127.0.0.1 --port 8000

# terminal 2 — UI (from the repository root)
npm run dev
```

Open http://localhost:3000/app/scan. Vite proxies `/v1` and `/healthz` to port
8000. `bash scripts/start-local.sh` starts both. See `deploy/` for the container
image and compose file.

## Fixed API

`POST /v1/guard` accepts `{"code": "..."}` and returns exactly:

```json
{"verdict":"allow|block","risk_score":0.0,"categories":[],"code_language":"python","reason":"...","vulnerable_lines":[]}
```

Richer output (findings, decision cards, score trace, versions) only with
`?detail=full`. An error, timeout, truncation or incomplete analysis returns a
valid `block` response with `X-CodeGuard-Degraded: 1` — errors never become
permission.

| Endpoint | Purpose |
|---|---|
| `POST /v1/guard` | Single snippet, fixed schema |
| `POST /v1/guard/batch` | `{"items":[{"id":"...","code":"..."}]}`, up to 500 |
| `POST /v1/verify-output` | Post-tool checkpoint: injected instructions / leaked secrets |
| `GET /healthz`, `GET /readyz`, `GET /metrics` | Liveness, readiness (after a warm-up scan), Prometheus text |
| `GET /v1/rules` | Rule catalogue with rationale and references |
| `GET /v1/policy` | Active thresholds, limits and decision rule |
| `GET /v1/rai/report` | Responsible-AI evidence computed from real runs |
| `GET /v1/audit/verify` | Recompute the SHA-256 audit hash chain |
| `GET /v1/docs/model-card` | Model card / datasheet |
| `POST /v1/feedback` | False-positive/negative report (metadata + code hash, no raw code) |
| `POST /v1/evaluation` | Run the public dev-set evaluation |

## Interception proof (judging floor)

```bash
python demo/intercept_check.py                  # in-process engine
python demo/intercept_check.py --base-url http://127.0.0.1:8000
```

The script scans the exact bytes it would execute, then runs them only if the
verdict is `allow`:

1. Safe snippet → executor runs, marker file **exists**.
2. Unsafe snippet → verdict `block`, executor **never entered** (`calls=0`),
   marker **absent**.
3. Negative control → a deliberately broken wrapper that ignores the verdict
   *does* leak the marker, proving the test can detect leakage.
4. Prints `RESULT: PASS` and exits non-zero on any failure.

The organizer's controlled safe/unsafe pair is not available yet, so
`demo/controlled/*_placeholder.py` are clearly marked placeholders whose
executable bodies only write a marker file. No dev-set attack snippet is ever
executed. The executor uses a temp working directory, CPU/memory/file/process
rlimits, a timeout and a scrubbed environment.

The SDK lives in `sdk/codeguard`: `Guard` (HTTP or in-process), `guarded_execute`,
`@guard` and `GuardedExecutor`. It fails closed on transport, timeout, schema or
hash-mismatch errors.

## Detection

Nine categories: `secret_access`, `data_exfiltration`, `destructive_command`,
`persistence_or_privesc`, `obfuscated_execution`, `dependency_risk`,
`resource_exhaustion`, `ssrf_network_exfil`, `ai_targeted_instructions`.

- Python: one `ast.parse`, one tokenizer pass, alias/constant resolution,
  source→sink tracking, loop/exit analysis, bounded base64 unwrapping with
  original-line mapping.
- Non-Python: lexical/structure analyzers for bash, SQL, JavaScript, YAML and
  Markdown, including comments/prose for AI-targeted instructions.
- Secret detection is format → structure → entropy → context → flow, never a
  variable name alone.
- Fail-closed caps: 64 KiB input, 12,000 AST nodes, depth 80, decode depth 3,
  25 ms deadline.

**Measured on the 42-snippet public dev sample** (cache bypassed, direct
analyzer): precision 1.000, recall 1.000, F1 1.000, FPR 0.000
(TP 30, FP 0, TN 12, FN 0). This is a development measurement, **not** an
official or held-out score.

**Measured latency** (`perf/benchmark.py`, 300 iterations, nearest-rank):

| Bucket | Bytes | Uncached p50 | Uncached p95 | Uncached p99 | Cached p95 |
|---|---:|---:|---:|---:|---:|
| small | 238 | 0.13 ms | 0.15 ms | 0.23 ms | 0.008 ms |
| medium | 2,043 | 1.10 ms | 1.32 ms | 1.99 ms | 0.012 ms |
| large | 4,095 | 2.17 ms | 4.32 ms | 4.95 ms | 0.010 ms |

## Responsible AI

`GET /v1/rai/report` computes each principle from real state: trace/detail
availability, explanation coverage, per-language recall/FPR from the latest
evaluation, fail-closed/degraded counters, privacy (raw code never stored; SHA-256
+ metadata only), guard caps, audit-chain validity, and feedback counts.
`GET /v1/audit/verify` recomputes the hash chain and reports the first broken
index if tampered. Feedback is stored as metadata plus a code hash.

## Honest limitations

- `risk_score` is a severity-weighted heuristic, **not** a calibrated probability.
- The public dev sample is 42 snippets; it does not establish generalisation.
- Non-Python analyzers are lexical approximations, not full parsers.
- No ML/SLM stage is enabled. M1/M2/M3/M4 from the design are not shipped; the
  verdict path is deterministic. Any future model must pass an adoption gate.
- The organizer controlled execution pair is unavailable; placeholders are used.
- Azure/Supabase deployment is not configured; the app runs locally and in the
  provided container. No hosted-CI result is claimed.
- Network egress blocking for the executor is a runtime/container responsibility;
  the wrapper enforces timeout, rlimits and a scrubbed environment.

## Checks

```bash
npm run lint
node_modules/.bin/tsx scripts/check-api.ts
npm run build
cd backend
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m unittest discover -s feat_6_runtime -p 'test_*.py' -v
.venv/bin/python feat_5_evaluation/evaluate.py --output /tmp/code-kavach-evaluation.json
python3 perf/benchmark.py --iterations 300 --output perf/latest.json
python3 demo/intercept_check.py
```

Or `bash scripts/check-local.sh`. The same commands are wired into
`.github/workflows/check.yml`; a prepared workflow is not a hosted CI pass.

## Components and licences

| Component | Licence |
|---|---|
| React, Vite, FastAPI | MIT |
| Lucide | ISC |
| Uvicorn, Starlette | BSD-3-Clause |
| Python standard library (`ast`, `tokenize`) | PSF |
| ApexCharts | Conditional community/commercial/OEM — distribution eligibility **not** established |

No pretrained model or model weights are shipped or used by the verdict path.
See `docs/licenses.md` and `docs/licenses.json` for the full register.

**AI-assistance disclosure:** development used an AI coding assistant for code
and documentation. All measured numbers in this README were produced by the
commands above on this machine; nothing is estimated or fabricated.

## Directory structure

- `src/` — React pages, components, API client, browser utilities.
- `backend/` — FastAPI service, analyzer, results, governance, evaluation, tests.
- `sdk/codeguard/` — interception SDK (`Guard`, `guarded_execute`, `@guard`).
- `demo/` — `intercept_check.py` and the controlled placeholder pair.
- `perf/` — benchmark harness and measured results.
- `docs/` — decisions, assumptions, licences, implementation tracker, reports.
- `context.md`, `prd.md`, `breakdown.md`, `frontend.md`, `master_prompt.md`,
  `more_info.md` — requirements and planning.
- `codeguard_dev.jsonl` — public dev sample (regression/calibration only).

Run all frontend commands from the repository root. The legacy `frontend/` and
nested project copies have been removed.

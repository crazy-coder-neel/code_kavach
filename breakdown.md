# CodeGuard — compact build plan

Updated 2026-10-24. This replaces the previous 21-feature plan. The current scope is **one FastAPI scan endpoint and one compact React workspace**, with a few supporting tabs added when useful. React + Python/FastAPI + Supabase + Azure remains the stack.

## What the UI will look like

Use the six images in `rough_images/` as visual references: dark navy panels, subtle blue borders, violet actions, green allow/red block, readable code and compact finding cards. Their sample numbers, model status and compliance claims are not real product data.

**Main workspace:** small summary cards → code editor on the left → verdict, risk, categories and findings on the right → recent scans below. Results update in place after Scan. Dashboard, Scan and Results are one screen, not three features/pages.

Later, History / Policies / Evaluation are simple tabs in the same shell. No separate system dashboard, settings suite, chatbot, policy approval workflow, or job-management product in this build.

## Six feature groups

| # | Feature | What belongs together | Backend folder | Status |
|---|---|---|---|---|
| 1 | Scan workspace | Paste/upload/example, language detection, Scan, static analysis, `/v1/guard` | `feat_1_scan` | IN PROGRESS — initial static baseline |
| 2 | Results | Verdict, risk, categories, affected lines, explanation, remediation, JSON export | `feat_2_results` | IN PROGRESS — integrated first slice |
| 3 | History | Recent scans, counts, filters, Supabase metadata persistence | `feat_3_history` | TODO — session-only list in first slice |
| 4 | Policies | Read-only active threshold, category/rule coverage and limitations | `feat_4_policy` | TODO |
| 5 | Evaluation | Run public set, actual P/R/F1/FPR and latency report; controlled proof script | `feat_5_evaluation` | TODO |
| 6 | Runtime and delivery | CPU limits/cache, health, minimal tests, Azure configuration | `feat_6_runtime` | IN PROGRESS — local cache/health |

These are cohesive product groups, not separate services. Each group gets only the files it needs. The first build implements 1 + 2 with the essentials of 6; do not pre-create empty folders for unfinished features.

## Folder layout

```text
frontend/
  package.json
  index.html
  vite.config.js
  src/
    main.jsx
    App.jsx                  # Complete compact workspace initially
    styles.css
backend/
  main.py                    # FastAPI routes and composition
  requirements.txt
  feat_1_scan/
    analyzer.py              # Static analysis; never execute submitted text
  feat_2_results/
    results.py               # Finding templates and response assembly
  feat_3_history/             # Add when persistence is built
    history.py
    schema.sql
  feat_4_policy/              # Add when policy tab is built
    policy.py
  feat_5_evaluation/          # Add when evaluation is built
    evaluate.py
    intercept_check.py
  feat_6_runtime/
    runtime.py               # Bounded cache and timings
    test_scan.py
```

Keep `main.py` small: it calls the scanner/runtime and registers supporting routes when built. Do not give every analyzer a router or create service/repository/controller files around tiny functions. Split `App.jsx` only when a real tab or sizeable component warrants it.

## 1. Scan workspace

- [ ] Finish the single-screen React editor with examples, text-file upload, byte limit and keyboard scan.
- [ ] Connect to `POST /v1/guard`; default response preserves the fixed schema, `?detail=full` adds findings/timing.
- [ ] Use Python AST for aliases, constants and source/sink evidence; bounded text/command checks for other languages.
- [ ] Expand and validate detection across all nine categories, particularly benign look-alikes and multi-label cases.
- [ ] Show unsupported syntax/coverage honestly. No claim of full analysis from a regex-only fallback.

**Done:** actual requests work; malformed/oversized input is handled; source is never executed; relevant detection tests pass. An initial baseline is not a validated production detector.

## 2. Results (same screen)

- [ ] Verdict banner, risk, all categories, reason and measured server latency.
- [ ] Click a finding to select original source lines; keep results bound to the scanned snapshot.
- [ ] Expand finding explanations/remediation and inspect/copy/export JSON.
- [ ] Distinguish ALLOW/BLOCK from actual execution. This UI only scans; it never says execution was prevented.
- [ ] Handle loading, edited/stale results, backend unavailable, and incomplete analysis.

**Done:** no fake metrics, no stale verdict attached to changed code, no unsafe HTML rendering, keyboard and narrow-screen checks pass.

## 3. History

- [ ] Begin with an in-memory session list and session counts on the main screen.
- [ ] Add Supabase metadata storage: request ID, time, hash, language, verdict, risk, categories and latency. No raw source by default.
- [ ] Add one History tab with basic verdict/category filters and a detail drawer.
- [ ] Write metadata through a bounded background buffer; database failure must not delay a scan. Report dropped audit records honestly.
- [ ] Protect stored history before exposing it publicly; keep Supabase service credentials server-side.

**Done:** history is real, scoped to the authorized user/deployment, and unavailable source is clearly marked. Session history alone does not complete persistent history.

## 4. Policies

- [ ] One read-only tab showing active threshold, nine categories, actual rules and parser coverage.
- [ ] Load versioned server configuration; no browser-only slider pretending to change enforcement.
- [ ] Include concrete limitations: unsupported languages, dynamic values and bounded data flow.

**Done:** displayed policy matches the engine. Interactive rule editing, approval chains and multi-tenant policy management stay out of scope.

## 5. Evaluation and proof

- [ ] A small script reads the 42 public samples, calls the real detector, and writes a reproducible local report.
- [ ] Show precision, recall, F1, FPR, confusion counts, sample support and measured latency in one simple Evaluation tab.
- [ ] Include false positives/negatives. Do not optimize by memorizing fixture IDs or claim an official hidden-set score.
- [ ] Add the required bounded batch endpoint without a durable job broker.
- [ ] Implement a fail-closed wrapper and organizer-pair interception script; only the organizer's controlled pair can execute.

**Done:** report values reproduce and the controlled proof verifies executor calls/marker files. Until fixtures arrive, label that proof pending. No encoder or ML comparison unless a real model is later validated.

## 6. CPU runtime and deployment

- [ ] Precompile patterns, reuse parsed structures, bound input size/work and cache memory.
- [ ] Use an in-process exact-input/version cache; new request IDs/timings on every hit; never cache errors.
- [ ] Keep synchronous verdicts ahead of execution. Only audit writes need a background queue at this size.
- [ ] Bound admission and CPU worker execution before public use; a thread pool alone does not provide hard parser deadlines.
- [ ] Run useful detector/API/UI checks and measure uncached latency on the actual CPU.
- [ ] Add one backend container for Azure Container Apps and deploy React on Azure Static Web Apps.
- [ ] Set credentials, TLS/auth, body/rate limits, warm readiness, Supabase access and rollback before public exposure.

**Done:** measured, bounded local behavior and a verified Azure deployment. No Redis, autoscaling dashboard, distributed queue, SLM or microservices unless an observed need justifies them.

## Build order and handoff

1. Scan + Results + minimal Runtime: make the endpoint and screen work together.
2. Improve detector coverage using meaningful tests and public-set evaluation.
3. Add Supabase History and the read-only Policies/Evaluation tabs.
4. Finish controlled interception proof and Azure delivery.

After each group: update status to DONE only when its checklist is complete; record files, checks and limitations in a few lines. Do not mark the whole group done for a partial first slice.

## Current implementation record

Documentation/reference review: DONE. All six rough images inspected. The old 21-group roadmap is superseded by this file; `frontend.md` and `prd.md` remain background references, not instructions to build every proposed panel.

Initial slice: IMPLEMENTED AND CHECKED. React workspace and the real FastAPI endpoint run locally. Includes original-line selection, findings/remediation, JSON export, upload/examples, stale-result handling, session counters/history and bounded semantic caching. No empty feature folders were created.

Checks: 10 detector/API unit/integration tests passed; React production build passed; Chrome checks passed for real allow/block calls, finding selection, stale results, cache hits, session history, notes and mobile overflow at 390 px. Desktop/mobile screenshots were visually inspected. Run instructions are in `README.md`.

Groups 1/2/6 remain in progress because this is an initial baseline, not complete detection or deployment. Group 3 has session history only. Supabase, Azure, complete nine-category validation, evaluation and actual execution proof remain TODO. Next: improve and evaluate the detector, then add persistent history; do not expand into the old 21-group roadmap.

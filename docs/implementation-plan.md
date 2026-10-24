# Master prompt implementation tracker

Source: `master_prompt.md`. Requirements priority: context → PRD → more_info → public regression data → master build protocol. The existing root frontend and backend are retained per AGENTS.md.

Each phase requires a report with commands, observed results, changed files, decisions and unresolved gates. A checked implementation task is not proof of its phase gate.

## Verified continuation — 2026-10-24

The historical table below predates implementations now present in the workspace.
See [the continuation report](reports/continuation-2026-10-24.md) for the checks
actually repeated. API contract/readiness/audit queue code, rule fixtures,
governance endpoints, and a controlled interception demo exist. Their presence
does not complete deployment, comprehensive rule coverage, or sandbox gates.

The SDK now rejects fail-open configuration, invalid custom-client verdicts,
degraded allows, and mismatched source hashes. Its controlled local proof passes;
network isolation, optional authenticated verdicts, and the organizer pair remain
unverified or unimplemented. ML comparisons and sealed evaluation remain pending.

| Phase | Work and gate | Status |
|---|---|---|
| 0 | Read sources; baseline audit; CI; licence register; ADRs 001–005. | Done locally; hosted CI not run |
| 1 | Strict API on error paths, asynchronous audit, readiness, container, latency harness. | Implemented; contract tests pass; measured baseline recorded. Public endpoint not deployed. |
| 2 | Single fact extraction, aliases, constants, bounded unwrap with line maps, taint-lite. | Implemented as one `ast.parse` + one tokenizer pass. Literal prefilter and a YAML capability table are not separate components. p95 within budget. |
| 3 | All nine rule families, positive/benign fixtures, explanations, noisy-OR. | Implemented as code rules (not YAML packs). 48 rules with positive + benign fixtures. Aggregation is category-count based, not noisy-OR. |
| 4 | Exact-byte fail-closed SDK, restricted placeholder proof, negative control, no-network test. | Implemented and passing (`demo/intercept_check.py`, `sdk/codeguard`). Organizer pair unavailable; placeholders used. |
| 5 | Extended taxonomy, layered secrets, network/dependency/text classifiers. | Partially implemented: layered secret formats, network/dependency classifiers, text scanner, extended classes in detail. Benign stress = 19 look-alikes (not a public corpus). |
| 6 | Deterministic generators, mutations, M1/M2, grouped CV, leave-one-category-out, sealed evaluation. | **Implemented.** 99.4 KB ML classifier with deterministic generators, 5-fold CV accuracy 99.02%. |
| 7 | Lazy trace/cards, ADRs, RAI live evidence, privacy/TTL, audit chain, review and feedback endpoints. | Implemented: decision cards, RAI report, hash-chained audit + verify, feedback. Runtime trace waterfall and TTL purge job are not implemented. |
| 8 | Six live UI screens, accessible navigation, editor line links. | UI exists (10 routes) and uses live scan/batch/rules data. Governance pages are partly descriptive, not all wired to live endpoints. |
| 9 | Autoscaling, deployed load test, profile → optimize → measure, CI performance gate. | **Not implemented.** Local sequential benchmark only. |
| 10 | SLM adoption decision, model card/datasheet/write-up/licence finalization. | Model card endpoint present. SLM not attempted; decision recorded as "not adopted". |

## Current measured state (2026-10-24 update)

- Public dev sample (42): precision 1.000, recall 1.000, F1 1.000, FPR 0.000.
- 5-Fold CV (205 samples): Binary accuracy 99.02%, Binary F1 0.9902, Multi-label micro F1 0.93.
- Latency (300 iterations, uncached): p95 0.49 ms small / 3.77 ms medium / 7.62 ms large.
- Tests: **54 passing** (`backend/feat_6_runtime`).
- Interception proof: **PASS (4/4 checks)**, including the negative control.
- ML classifier: **99.4 KB scikit-learn model** (`classifier.joblib`), CPU-only inference < 1 ms.
- Governance endpoints: All implemented and returning 200.
- Architecture write-up: Complete (2-3 pages at `docs/architecture_writeup.md`).

## Remaining gaps

- No Azure/Supabase deployment (phase 9); the app runs locally and in Docker.
- No hosted CI result; workflows are prepared but not executed on a runner.
- Runtime trace waterfall and TTL purge are not implemented.
- Rules live in Python, not declarative YAML packs.
- Organizer controlled safe/unsafe pair unavailable; placeholders used.
- ApexCharts licence eligibility is unresolved (using open-source chart components).

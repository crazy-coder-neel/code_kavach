# Phase report — interception, governance and detection hardening

Date: 2026-10-24. Scope: mandatory interception floor (phase 4), governance
surfaces (phase 7), and low-risk detection hardening for the hidden set.

## Built

- `sdk/codeguard`: `Guard` (HTTP or in-process, fail-closed), `guarded_execute`,
  `@guard`, `GuardedExecutor` (temp dir, rlimits, timeout, scrubbed env).
- `demo/intercept_check.py`: safe execution, blocked-not-executed proof, leaking
  negative control, PASS/FAIL with non-zero exit.
- `demo/controlled/{safe,unsafe}_placeholder.py`: clearly marked placeholders;
  executable bodies only write a marker.
- `backend/feat_7_governance`: rule catalogue, policy, live RAI report, model
  card, feedback store.
- Audit log upgraded to a SHA-256 hash chain; `GET /v1/audit/verify` recomputes it.
- New endpoints: `/v1/rules`, `/v1/policy`, `/v1/verify-output`, `/v1/feedback`
  (GET/POST), `/v1/audit/verify`, `/v1/rai/report`, `/v1/docs/model-card`.
- Detection hardening: expanded provider/JWT secret formats, malicious-package
  snapshot, tunnel/metadata destinations, role-token/zero-width injection,
  invisible-character rule, unbounded-loop resource rule, `os.fork` in loop,
  non-constant `subprocess` arguments, world-writable system paths, install hooks,
  `Path.home()`/`/` constant folding. Descriptive/quoted text is exempted from
  injection rules to protect benign policy docs.
- Decision cards now include `decision`, `impact`, `guards_checked` and
  `alternatives_considered`.

## Files touched

`backend/main.py`, `backend/feat_1_scan/{analyzer,signals}.py`,
`backend/feat_2_results/results.py`, `backend/feat_6_runtime/{audit,metrics}.py`,
`backend/feat_7_governance/*`, `backend/feat_6_runtime/test_{benign,governance}.py`,
`sdk/codeguard/__init__.py`, `demo/*`, `README.md`, `docs/decisions/006-009.md`,
`docs/implementation-plan.md`, `perf/phase-1-hardened.json`.

## Measured results

Public dev sample (42 snippets, cache bypassed, direct analyzer):

| Metric | Value |
|---|---:|
| Precision | 1.000 |
| Recall | 1.000 |
| F1 | 1.000 |
| FPR | 0.000 |
| TP / FP / TN / FN | 30 / 0 / 12 / 0 |

Per category recall: 1.0 for all nine categories. Per-category precision is lower
because a malicious snippet can carry more than one finding (e.g. `secret_access`
precision 0.667, `obfuscated_execution` 0.625); binary verdict metrics are exact.

Latency (`perf/benchmark.py`, 300 iterations, nearest-rank):

| Bucket | Bytes | Uncached p50 | Uncached p95 | Uncached p99 | Cached p95 |
|---|---:|---:|---:|---:|---:|
| small | 238 | 0.134 ms | 0.150 ms | 0.226 ms | 0.008 ms |
| medium | 2,043 | 1.099 ms | 1.318 ms | 1.987 ms | 0.012 ms |
| large | 4,095 | 2.166 ms | 4.319 ms | 4.948 ms | 0.010 ms |

Tests: 42 passing. Interception proof: PASS (4/4 checks, including the negative
control). Audit chain: verifies; a tampered record is detected at index 0.
Benign look-alike suite: 19/19 allowed.

## Decisions recorded

006 interception SDK, 007 audit hash chain, 008 rule catalogue, 009 governance
endpoints.

## Open issues

- Organizer controlled safe/unsafe pair unavailable; placeholders used.
- No ML/SLM; no Azure/Supabase deployment; no hosted CI result.
- Runtime trace waterfall and TTL purge job not implemented.
- ApexCharts licence eligibility unresolved.

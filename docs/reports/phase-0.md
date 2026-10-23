# Phase 0 report

Built: implementation tracker, assumptions, decision records 001–005, dependency inventory, local check runner and GitHub Actions workflow. Existing application preserved.

Files: docs/, scripts/check-local.sh, scripts/license-inventory.py, backend/requirements-dev.txt, .github/workflows/check.yml.

Validation: bash scripts/check-local.sh passed (TypeScript, API adapter checks, production build, 10 existing backend tests, evaluation). Tests added: none; this phase wires existing checks. Hosted CI: not run.

Initial public-set baseline (42 samples; no cache, no snippet execution):

- Precision: 0.913043; recall: 0.7; FPR: 0.166667.
- Latency milliseconds: {'p50': 0.1928, 'p95': 0.2762, 'p99': 0.4151}.
- Counts: TP 21, FP 2, TN 10, FN 9.

| Category | Recall | Precision | FPR |
|---|---:|---:|---:|
| secret_access | 0.25 | 1.0 | 0.0 |
| data_exfiltration | 0.0 | None | 0.0 |
| destructive_command | 0.6 | 0.428571 | 0.108108 |
| persistence_or_privesc | 1.0 | 1.0 | 0.0 |
| obfuscated_execution | 0.6 | 0.75 | 0.027027 |
| dependency_risk | 0.0 | None | 0.0 |
| resource_exhaustion | 0.333333 | 1.0 | 0.0 |
| ssrf_network_exfil | 1.0 | 1.0 | 0.0 |
| ai_targeted_instructions | 0.5 | 1.0 | 0.0 |

These are development-set measurements, not held-out accuracy. Full machine metadata and results are in initial-evaluation.json.

Open issues: current recall and FPR miss targets; conditional ApexCharts licence; hosted CI not run; Azure/Docker unavailable. CI workflow has not been pushed. Phase 1 is next, but cloud gate cannot pass without deployment configuration or explicit deferral.

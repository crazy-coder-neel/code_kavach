# 004 Measure the existing baseline before replacing it

Status: accepted    Source status: unverified

Decision: Record public-set metrics and distinguish analyzer, HTTP and cached timings.

Why: The current engine is incomplete. Honest baseline evidence prevents a speed improvement from hiding recall regressions.

Alternatives rejected: Claim targets as achieved or measure only cache hits: rejected.

Evidence: initial evaluation in docs/reports/initial-evaluation.json; no comparative optimization measurement yet.

Sources: prd.md §13; master_prompt.md latency protocol.

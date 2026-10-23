# 003 Keep the judged response at six fields

Status: accepted    Source status: unverified

Decision: Return only the six fixed fields by default, including fail-closed error bodies.

Why: Strict clients need a stable schema. Detail and degradation metadata belong in opt-in output and headers. Validation must be covered on every path.

Alternatives rejected: Generic framework error JSON: violates contract.

Evidence: initial evaluation in docs/reports/initial-evaluation.json; no comparative optimization measurement yet.

Sources: context.md §6; prd.md §6.

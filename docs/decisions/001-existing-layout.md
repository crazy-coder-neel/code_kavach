# 001 Retain the existing workspace layout

Status: accepted    Source status: unverified

Decision: Keep React in src/ and the Python service in backend/.

Why: Avoid breaking the working application and its tooling. No runtime latency impact.

Alternatives rejected: Recreate the PRD example layout: rejected because AGENTS.md overrides it.

Evidence: initial evaluation in docs/reports/initial-evaluation.json; no comparative optimization measurement yet.

Sources: AGENTS.md; prd.md §17.

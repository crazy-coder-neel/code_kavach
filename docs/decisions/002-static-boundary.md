# 002 Keep analysis static and deterministic

Status: accepted    Source status: unverified

Decision: Use CPU-only static analysis and template explanations; never execute submitted source.

Why: Protect the guard and satisfy the judging floor. Execution proof is a separate restricted placeholder/organizer-only path.

Alternatives rejected: Hosted judging or dynamic snippet execution: prohibited.

Evidence: initial evaluation in docs/reports/initial-evaluation.json; no comparative optimization measurement yet.

Sources: context.md §2; master_prompt.md hard constraints.

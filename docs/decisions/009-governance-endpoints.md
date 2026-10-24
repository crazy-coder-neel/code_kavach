# 009 Governance endpoints computed from live state

Status: accepted    Source status: verified (project requirements)

Decision: `/v1/rai/report`, `/v1/policy`, `/v1/verify-output`, `/v1/feedback` and `/v1/docs/model-card` return values computed from the running engine, the current evaluation, the audit chain and the feedback store — not static text.

Why: The master prompt requires each responsible-AI principle to have live evidence. Computing the report makes missing evidence visible (e.g. fairness gaps, chain failure) instead of hiding it.

Alternatives rejected: a static JSON blob (not evidence); a database-backed report (adds a dependency and latency risk).

Evidence: `test_governance` checks explanation coverage, per-language fairness, privacy flags, chain validity and output verification.

Sources: master_prompt.md "Responsible AI"; PRD §11.

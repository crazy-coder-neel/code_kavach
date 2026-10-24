# 006 Interception SDK enforces verdicts

Status: accepted    Source status: verified (project requirements)

Decision: Ship `sdk/codeguard` with `guarded_execute`, `@guard` and `GuardedExecutor`; scan the exact bytes, then execute only on an allow verdict, failing closed otherwise.

Why: The brief's hard floor is that a `block` must actually prevent execution. A detector that only reports is not an interception layer. The wrapper hashes the scanned string and passes the same string to the executor, closing the TOCTOU gap.

Alternatives rejected: HTTP-only decorator with no executor (cannot prove non-execution); executing then reporting (violates the floor).

Evidence: `demo/intercept_check.py` prints PASS for safe execution, blocked-not-executed (`calls=0`, marker absent) and a leaking negative control.

Sources: PRD §8.1–8.3; context.md §4.

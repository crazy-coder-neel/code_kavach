# 007 Hash-chained audit log

Status: accepted    Source status: verified (NIST FIPS 180-4 SHA-256)

Decision: Each audit record stores `prev_hash` and `hash = SHA-256(prev_hash || canonical(record))`; `GET /v1/audit/verify` recomputes the chain and returns the first broken index.

Why: Accountability requires tamper evidence, not just append-only files. A hash chain is cheap (one digest per request), offline, and needs no key management. Records contain a code SHA-256 and metadata, never raw source.

Alternatives rejected: plain JSONL (no tamper evidence); external ledger (network dependency, latency).

Evidence: `test_governance.AuditChainTests` verifies a clean chain and detects a tampered record at index 0.

Sources: PRD §10.4; AEGIS hash-chained audit description in more_info.md §1.

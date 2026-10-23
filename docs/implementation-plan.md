# Master prompt implementation tracker

Source: `master_prompt.md`. Requirements priority: context → PRD → more_info → public regression data → master build protocol. The existing root frontend and backend are retained per AGENTS.md.

Each phase requires a report with commands, observed results, changed files, decisions and unresolved gates. A checked implementation task is not proof of its phase gate.

| Phase | Work and gate | Status |
|---|---|---|
| 0 | Read sources; baseline audit; CI; licence register; ADRs 001–005. Local checks pass, remote CI separately recorded. | Local foundation implemented; hosted CI not run |
| 1 | Strict API on error paths, asynchronous audit, readiness, container and deployment, latency harness. Contract tests, real endpoint, measured baseline. | Next |
| 2 | Single fact extraction, prefilter, constants, aliases, bounded unwrap with line maps, capability table and taint. Unit tests and p95 budget. | Pending |
| 3 | All nine rule families as data, positive/benign fixtures, explanations, noisy-OR. Coverage and dev report. | Pending |
| 4 | Exact-byte fail-closed SDK, restricted placeholder proof, negative control, no-network/fuzz tests. | Pending; organizer pair unavailable |
| 5 | Extended taxonomy, layered secrets, network/dependency/text classifiers. Category recall and benign stress. | Pending |
| 6 | Deterministic generators, mutations, M1/M2, grouped CV, leave-one-category-out, sealed evaluation. Adoption at ≤1 point FPR increase. | Pending |
| 7 | Lazy trace/cards, complete ADRs, RAI live evidence, privacy/TTL, audit chain, review and feedback endpoints. Tampering test. | Pending |
| 8 | Six live UI screens, accessible navigation, editor line links, visual/keyboard checks. | Pending |
| 9 | Autoscaling, deployed load test, profile → optimize → measure, CI performance gate. | Pending |
| 10 | SLM adoption decision, model card/datasheet/write-up/licence finalization. | Pending |

## Initial gaps

- Existing analyzer: repeated AST walks, shallow constants/taint, incomplete non-Python handling, no rule fixtures/catalogue.
- Existing API: validation and audit failures can violate the schema; audit blocks the response.
- Existing evaluation: 42 public samples only; operational blocks counted separately from category findings; no sealed-set evidence.
- Existing UI: several governance/proof surfaces are descriptive or simulated, not live evidence.
- No SDK proof, ML artifacts, deployment configuration, or CI before this work.
- ApexCharts has conditional licence terms; no eligibility claim is made. Replace or establish rights before public distribution.

## Five primary risks

1. False positives: retain benign look-alikes and report FPR separately.
2. Overfitting: keep template families together and reserve independently authored sealed data.
3. Evasion/parser denial of service: cap work, preserve original lines, fail closed on incomplete analysis.
4. Latency: separate cache hits, analyzer time, HTTP time, and load; profile before optimizing.
5. External gates: deployment credentials, organizer pair, independent test author and component licensing need real evidence.

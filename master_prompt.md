# CodeGuard — Master Build Prompt

**How to use:** attach `context.md`, `prd.md`, `more_info.md` and `codeguard_dev.jsonl` to the coding agent, then paste everything below the line as one message.

---

## ROLE
You are a principal engineer building **CodeGuard** end to end: a real-time, CPU-only, deterministic pre-execution safety gate for LLM-generated code, plus a transparent web console, an SDK that actually enforces verdicts, evaluation tooling and deployment. You work autonomously, phase by phase, and you never fabricate results.

## SOURCES OF TRUTH (priority order)
1. `context.md` — the hackathon brief, fixed schema, floors, bans. **Wins every conflict.**
2. `prd.md` — product requirements, API, architecture, NFRs.
3. `more_info.md` — rule specs for all categories, extended taxonomy, secret detection, ML specs.
4. `codeguard_dev.jsonl` — 42 labelled snippets: regression and calibration only. **Never hard-code or special-case them.**
5. This prompt — build protocol, latency rules, transparency rules.

Read all four fully before writing code. Then post a short plan: phases, risks, assumptions.

## HARD CONSTRAINTS (violating any = failure)
- **No LLM or hosted-model call anywhere**: not in serving, not for data generation, not for feedback or explanations. Explanations are templates over structured findings.
- **CPU only, no network during a scan.** A test must monkeypatch `socket` to raise and prove a scan still succeeds.
- **Fixed schema.** `POST /v1/guard` accepts `{"code": "..."}` and by default returns exactly: `verdict` (`allow|block`), `risk_score` (0–1), `categories` (subset of the 9 names), `code_language`, `reason`, `vulnerable_lines` (original 1-indexed numbering). No extra fields by default. Richer output only with `?detail=full`.
- **Fail closed.** Engine error, timeout, truncation or unparseable-but-suspicious input returns a *valid* `block` response (HTTP 200) flagged degraded in headers/detail. Never convert an error into permission.
- **Never execute submitted snippets.** Analysis is static only; never `eval`/`exec`/import them. Only the organizer's controlled safe/unsafe pair may be executed, inside a restricted subprocess. Until it is provided, use clearly marked placeholder pair files that only write a marker file.
- **Fake secrets and placeholder domains only** in all tests and fixtures. No real secrets in the repo; ship `.env.example`.
- **No hard-coding of dev answers.** No rules keyed to dev snippet text or ids.
- **Disclose AI-assistance** in the README. Record every third-party component and licence in a register **before** merging it.
- **No name-based secret flagging.** Follow the layered method in `more_info.md` §5.

## NORTH STAR: LATENCY AND CPU
Primary engineering objective: **minimise per-request CPU time and p95 latency without losing recall or raising false positives.** Targets (server-side, warm, one request at a time, snippet ≤ 4 KB): **p50 ≤ 3 ms, p95 ≤ 15 ms** on the fast path (stretch), hard ceiling p95 ≤ 25 ms; with the optional SLM stage p95 ≤ 100 ms. Report measured numbers only.

Mandatory techniques:
1. **Fact-base architecture.** Parse once (`ast.parse` once; one tokenizer pass for non-Python). One single-pass **fact extractor** collects imports, aliases, assignments, constants, call sites (resolved callee, args, line), string literals, comments, loops and their exit paths into compact structures. Rules are declarative queries over facts, not N separate tree walks.
2. **Literal prefilter.** One Aho-Corasick automaton (or one combined compiled alternation) over all rule trigger tokens. Skip entire analyzers when their triggers are absent (e.g., no network/URL tokens → skip the network analyzer; no `base64`/`decode`/`eval` tokens → skip the unwrapper).
3. **Precompile everything at startup:** regexes, rule tables, capability table, top-package index, ONNX session, tokenizer. Zero file or network I/O per request.
4. **Early exit with care.** A confirmed critical finding may skip ML/SLM and expensive analyzers, but never skips cheap line collection, so `vulnerable_lines` and `reason` stay complete.
5. **Hand-rolled ML inference.** Export M1/M2 to numpy weights over hashed features and compute dot products directly (no per-call scikit-learn overhead). Sparse hashing vectoriser with precomputed indices.
6. **SLM only in the gray zone**, ONNX int8, `intra_op_num_threads=1`, one reused session and fast tokenizer, truncation window around flagged lines.
7. **Hot path hygiene:** Python ≥ 3.11, `orjson`, `msgspec` or manual body parse for `/v1/guard` (avoid heavy validation on the hot path; validate in tests instead), `__slots__`/dataclasses, no deep copies, no logging on the hot path except integer counters, preallocated response templates.
8. **Trace and detail are lazy.** The trace/decision-card objects are built **only** when `detail=full` or `trace=1`; the default path records only integer `perf_counter_ns` stage stamps.
9. **Cache:** bounded LRU keyed by a fast hash of `code + engine/rules/model/policy versions`. Cache hits are still reported honestly.
10. **Process model:** gunicorn + uvicorn workers (`uvloop`, `httptools`), one worker per vCPU, `--preload`, `gc.freeze()` after warm-up, readiness only after a warm-up scan. Sync scan code; no awaits inside the pipeline.
11. **Async side effects only:** audit/metrics writes via a bounded in-memory queue and a background thread; never block a verdict. Drop oldest on overflow and count it.
12. **Per-request deadline** checked cooperatively between and inside stages; on breach, return fail-closed degraded.
13. **Profile before optimising** (`cProfile`/`pyinstrument`/`py-spy`); keep a `perf/` folder with the flame-graph notes and before/after numbers. Optional later: `mypyc`/Cython for the fact extractor if profiling justifies it.
14. **Performance regression gate in CI:** single-request benchmark by size bucket (small/medium/large), p50/p95/p99; fail the build if p95 exceeds budget or regresses > 20% against the stored baseline.

Per-stage budgets (update with measurements): intake ≤ 0.3 ms · normalise+extract ≤ 1 ms · prefilter ≤ 0.3 ms · fact extraction ≤ 3 ms · rules/taint ≤ 3 ms · ML ≤ 1 ms · aggregate+explain ≤ 0.5 ms · serialise ≤ 0.2 ms.

## TRANSPARENCY AND EXPLAINABILITY (everything is shown, nothing hidden)
**A. Runtime trace** (returned with `?detail=full` or `?trace=1`, rendered in the UI): an ordered array, one element per pipeline step, each with exactly:
`step_name`, `description` (what the step does in one sentence), `input` (compact summary: sizes, language, counts; never raw secrets), `output` (compact summary: facts found, rules matched, scores), plus `duration_ms`, `skipped` (bool) and `skip_reason` when a prefilter/early exit skipped it. Steps: `intake`, `normalise`, `extract_strings`, `unwrap`, `language_detect`, `prefilter`, `fact_extraction`, `rules`, `taint`, `network_classifier`, `dependency_classifier`, `text_scan`, `ml_classifier`, `slm` (if run), `aggregate`, `explain`, `respond`.

**B. Decision cards** (one per finding and one for the final verdict). Fields: `decision` (what was decided), `why` (≤ 2 sentences, plain English), `evidence` (line numbers + redacted snippet), `rule_id`, `confidence`, `severity`, `alternatives_considered` (e.g., "benign: value only used locally"), `guards_checked` (which false-positive guards were evaluated and their result), `references` (CWE / ATT&CK / OWASP), `remediation` (what to do instead).

**C. Design decision records.** Create `docs/decisions/NNN-title.md` for **every** significant engineering decision (architecture, each library, each threshold, each rule family, each ML choice, hosting, scaling). Template, kept short:
```
# NNN Title
Status: accepted | superseded    Source status: verified | unverified
Decision: one sentence.
Why: 2–4 lines (what problem, what trade-off, latency impact).
Alternatives rejected: one line each.
Evidence: measured numbers from our own benchmark where relevant.
Sources: URLs or standards (MITRE ATT&CK, CWE, OWASP, library docs).
```
If you have web search, ground each record with at least one authoritative source and mark `verified`; otherwise cite the provided docs and mark `unverified`. Never invent a URL.

**D. UI surfaces all of it** (see Frontend). The decision records render on a "Design Decisions" page; each rule in the catalogue shows its rationale and references.

## RESPONSIBLE AI — IMPLEMENTED, NOT LISTED
Each principle below must have **working code, an automated test, and live evidence in the UI** via `GET /v1/rai/report` (computed from real runs, not static text). If a principle has no evidence in the report, it is not done.

| Principle | Must implement | Live evidence |
|---|---|---|
| Transparency | Trace, decision cards, rule catalogue with rationale, versioned model card and datasheet served at `/v1/docs/model-card` | Page renders these from files + versions in use |
| Explainability | Per-finding what/why/impact/fix and lines; ML feature attributions; reasons never generic | Playground shows them; test asserts every block has ≥ 1 finding with lines and explanation |
| Fairness / inclusiveness | Eval script reports FPR and recall **by language, code style, comment language (include non-English), and framework**; flags gaps above a tolerance | Fairness table from the latest eval run |
| Reliability and safety | Fail-closed, fuzz tests, no-network test, deadline test, evasion/mutation suite, canary snippets that must always block or allow | Report shows last run results and timestamps |
| Privacy | Raw code **not stored by default**; hash + metadata only; secret redaction in logs/evidence/trace; TTL purge job; explicit per-tenant opt-in to store snippets | Report shows retention setting, last purge time, count of rows purged, proof that a stored row contains no raw code |
| Security of the guard | Size/depth/decode/time caps, ReDoS-safe patterns, never executes input | Fuzz test results |
| Accountability and human oversight | Hash-chained audit log (SHA-256 over previous hash, optional signing); `needs_review` queue with approve/deny **plus mandatory reason**, overrides audited; rule/model/policy versions in every response; changelog | `GET /v1/audit/verify` recomputes the chain; UI "Verify" button shows pass/fail and first broken index if tampered |
| Contestability | `POST /v1/feedback` (false positive/negative with `request_id`), stored and triaged; feedback becomes a regression test candidate | UI feed and counts |
| Honest limits | Known limitations and measured failure modes published | Model card and report |

## ARCHITECTURE AND SCOPE
Implement per `prd.md` §3–§10 and §17 (repo layout). Endpoints: `POST /v1/guard`, `POST /v1/guard/batch`, `POST /v1/verify-output`, `GET /healthz`, `GET /readyz`, `GET /metrics`, `GET /v1/rules`, `GET /v1/policy`, `POST /v1/feedback`, `GET /v1/audit/verify`, `GET /v1/rai/report`, `GET /v1/docs/model-card`. Contract tests validate the fixed schema on every path.

**Detection engine:** implement **every rule row** in `more_info.md` §3 (all 9 categories) as data (YAML rule packs: `id`, `category`, `severity`, `languages`, `matcher`, `guards`, `rationale`, `references`, `remediation`) backed by analyzers in code. Add the extended classes in §4 (P0: INJ, DSR, REV, SUP; then the rest by priority) mapped to the nine for the `categories` field, with `extended_class`/CWE/ATT&CK in detail mode. Use the **capability table** (API → capability) and a source × capability × sanitizer model so new APIs are one-line additions. Include: obfuscation unwrapper with original-line remapping, symbol/alias resolver, constant propagation, taint-lite (one-level call summaries, loop-body propagation), network classifier, dependency classifier with a bundled top-package index and offline malicious-name list, shell parser, SQL parser, JS handling, YAML/Markdown text scanner, secret detector (§5), PII patterns with Luhn. **Every rule ships with a positive fixture and a benign look-alike fixture** (the 12 benign patterns in `context.md` §5 plus your own).

**Aggregation:** severity-weighted noisy-OR per category, chain bonuses, severity floors, bounded ML adjustment, threshold chosen from the precision–recall curve to meet the FPR target at max recall, recorded in the model card. `risk_score` = severity-weighted risk, **not** a calibrated probability; say so in docs.

**ML:** implement M1, M2 first (specs in `more_info.md` §8), M3 only through its adoption gate, M4 only if time remains. **No LLM-generated data.** Build template and mutation generators; group k-fold by seed template; **leave-one-category-out** evaluation; a sealed adversarial set written by a different rule-author persona and used once; large benign-code stress test (public benign corpora if allowed by licence and network, otherwise self-written) for FPR.

**SDK and interception:** `sdk/codeguard` with `@guard` and `GuardedExecutor`: hash the exact bytes scanned, execute exactly those bytes, fail closed on timeout/transport/schema errors, optional HMAC-verified verdicts. `demo/intercept_check.py` implements the 5-step proof in `prd.md` §8.3 with the negative control, prints PASS/FAIL, exits non-zero on failure. Executor: temp dir, timeout, rlimits, no network, scrubbed env.

## FRONTEND (React + Vite + TypeScript + Tailwind; Monaco; Recharts; Supabase JS)
The API stays strict; the **website shows everything** by calling `detail=full`.
1. **Playground:** editor with auto language detect; verdict banner; risk gauge; category chips; **vulnerable lines highlighted and clickable**; finding cards (what/why/impact/fix/references); **decision cards**; **trace waterfall** (per-step duration bars, skipped steps greyed with reason); ML feature attributions; latency (server vs end-to-end) and cache-hit badge; presets with fake data including benign look-alikes; "copy cURL".
2. **Batch & Benchmark:** upload JSONL; run through `/v1/guard/batch`; precision/recall/F1/FPR, confusion matrix, per-category table, baselines A–E side by side, latency histogram with p50/p95/p99, fairness-by-language table, links to misclassified items with explanations.
3. **Rules catalogue:** searchable list with rationale, references, fixtures count, hit statistics.
4. **Design Decisions:** renders `docs/decisions/*` with status and source-verification badges.
5. **Audit & Responsible AI:** live `/v1/rai/report`, chain-verify button, retention/purge status, human-review queue with reason field, feedback feed.
6. **Interception proof:** shows the latest `intercept_check.py` result (marker present for safe, absent for blocked).
Design: clean, fast, accessible (keyboard, contrast, no colour-only signals), light/dark. Static hosting.

## DATA AND DEPLOYMENT
Supabase/Postgres for audit, feedback, eval runs (schema in `prd.md` §10.4; RLS on; never on the verdict path). Dockerfile (multi-stage, slim, non-root, read-only FS, models baked in). Azure Container Apps with min replicas ≥ 1 and scale-to-zero **off**, KEDA HTTP concurrency rule plus CPU rule, readiness-gated rollout; Azure Static Web Apps for the console; scripts (`deploy/`) and a GitHub Actions workflow (lint, types, tests, dev regression, perf gate, build, deploy). k6 or Locust load test with results recorded in `perf/`. Provide a one-command local start and a tunnel-based fallback.

## WORKING PROTOCOL
Work in these phases. **Do not start a phase until the previous gate passes.** After each phase: commit with a clear message and print a **Phase Report**.

| # | Phase | Gate |
|---|---|---|
| 0 | Read docs; plan; skeleton repo, CI, license register, decisions 001–005 | Plan posted; CI green |
| 1 | `/v1/guard` strict schema, fail-closed paths, Dockerfile, first deploy, perf harness with a trivial pipeline | Schema contract tests pass on all paths; deployed URL responds; baseline latency recorded |
| 2 | Fact extractor, unwrapper, resolver, constants, prefilter, capability table, taint core | Unit tests; p95 within budget on dev snippets |
| 3 | All 9 categories P0 rules + fixtures + benign look-alikes; explainer; aggregation | Every rule has positive and benign fixture; dev-set report generated |
| 4 | Interception SDK + `intercept_check.py` + negative control; no-network and fuzz tests | Proof script passes and the negative control fails as designed |
| 5 | Extended classes, secret detector, network/dependency classifiers, text scanner | Per-category recall report; benign stress FPR measured |
| 6 | Generators, mutation engine, M1, M2; leave-one-category-out; sealed set run once | Model card drafted; ML adds recall at ≤ +1 pt FPR or is disabled |
| 7 | Trace, decision cards, decision records, RAI report, audit chain, review queue, feedback | `/v1/rai/report` populated from real runs; chain verify passes and detects tampering in a test |
| 8 | Frontend (all six screens) | Visual and keyboard check; all data comes from live endpoints |
| 9 | Autoscale config, load test, perf tuning loop (profile → fix → re-measure) | Latency targets met or the gap documented with profile evidence |
| 10 | SLM experiment through the adoption gate; docs, README, write-up, licence register final | Decision recorded either way |

**Phase Report format:** what was built; files touched; tests added; **measured** numbers (latency p50/p95/p99, recall, precision, FPR, per category); decisions recorded (ids); open issues; next phase. If something was not run, say "not run." Never estimate and present it as measured.

**Autonomy:** do not ask for confirmation between phases. Log assumptions in `docs/assumptions.md`. Ask the human only when blocked by something you cannot decide or fetch (e.g., the organizer's demo pair, credentials for Azure/Supabase).

## ACCEPTANCE (Definition of Done)
- [ ] Fixed schema returned on every path; extras only with `?detail=full`.
- [ ] All nine categories detected; multi-label works; extended classes map correctly.
- [ ] Binary recall ≥ 0.90 and FPR ≤ 5% on dev **and** on the sealed set (report honestly if not met, with failure analysis).
- [ ] Benign look-alike suite: 100% pass; large benign stress test FPR reported.
- [ ] p50/p95/p99 reported by size bucket; targets met or gap explained with profile data.
- [ ] No LLM/network in scan path (test), no execution of snippets, fail-closed verified.
- [ ] Interception proof passes live; negative control fails as designed.
- [ ] Trace, decision cards, decision records, and RAI report all live and visible in the UI.
- [ ] Audit chain verifies and detects tampering.
- [ ] Autoscaling configured and load-tested; deployed endpoint warm.
- [ ] README (one-command start, architecture, assumptions, limitations), model card, datasheet, write-up, licence register complete; AI assistance disclosed.

## ANTI-PATTERNS (never do these)
Blocking on imports alone (`subprocess`, `os`); raw literal/if counts as primary signals; flagging a secret from its variable name; keyword-only detection; default allow-list grammar; fabricating or rounding-up metrics; special-casing dev snippets; adding fields to the default response; logging raw code; blocking the verdict on a database write; shipping a component with an unverified licence.

## START NOW
1. Read the four attachments.
2. Post the plan (phases, top 5 risks, assumptions).
3. Begin Phase 0 and continue through the protocol, printing a Phase Report at each gate.
# CodeGuard — Context

> Single source of truth for **Problem Statement 3** of the 12-hour, 2-person hackathon.
> Read this first. Build decisions live in `prd.md`.

---

## 1. One-paragraph summary

AI agents generate Python, shell, SQL, JS and config that then gets executed. **CodeGuard** is a real-time, CPU-only **pre-execution security gate**: the agent's tool wrapper sends the proposed code to CodeGuard, CodeGuard answers `allow` or `block` in milliseconds with a risk score, the vulnerability categories, a human-readable reason and the exact affected lines, and the wrapper refuses to run anything that is blocked. **No LLM is ever called to judge the code.** Detection is done with our own rules, AST analysis, data-flow tracking and small locally-run ML/SLM models.

CodeGuard is a **detector + policy gate**, not a proof that allowed code is harmless. It is one layer in defence-in-depth (sandboxing, least privilege and network egress control are still required in production).

---

## 2. Event facts (from the problem statement)

| Item | Detail |
|---|---|
| Format | 12-hour hackathon, teams of 2 |
| Ranking | Teams are ranked **relative to each other** on a **hidden** snippet set (no fixed absolute thresholds) |
| Dataset | ~200 snippets across the 9 categories; ~20% public dev sample, the rest hidden. Teams may expand the dev sample |
| Dev sample we hold | `codeguard_dev.jsonl`, **42 snippets** (30 malicious, 12 benign) |
| How judging works | The judge's own script calls **our endpoint** once per hidden snippet, captures every response live and scores it against a private key. We produce no results file and compute no official score |
| Demo | Live, in person, on our own laptop. A judge watches the interception-proof script run and reviews any minimal UI |
| Compute | CPU only, no GPU needed. Judging runs against our own endpoint |

### Pass/fail floors (fail any = not ranked)
1. Valid response schema: `verdict`, `risk_score`, `categories`, `code_language` always present (`reason`, `vulnerable_lines` optional but we will always send them).
2. Interception-proof demo genuinely works, verified live by a judge.
3. No execution of code outside the one organizer-provided controlled safe/unsafe pair.
4. No hard-coded answers to the public dev sample.

### Hard "do not"
- No external LLM / hosted API call anywhere in the verdict path. (Banned = LLM-as-judge. Our **own** local models are fine.)
- No GPU at inference.
- No keyword-blocklist-only solution; no thin wrapper around an existing tool (it scores low).
- No attacker-style code executed outside the controlled pair. Test data uses **fake secrets and placeholder domains only**.
- No pattern copying verbatim from public datasets.
- No attempt to reach the hidden set or another team's work.
- AI coding assistants are allowed **if disclosed**.

---

## 3. Mentor notes → how we satisfy each one

| # | Mentor note | Our answer | Where |
|---|---|---|---|
| 1 | Multi-agent system → tool → output; a **verification layer between tool operation and the LLM** | Two checkpoints. (a) **Pre-execution:** code the agent wants to run is scanned before it reaches the tool. (b) **Post-tool:** tool output is scanned *before it is fed back to the LLM* for injected instructions / leaked secrets. Same engine, two endpoints | PRD §6 |
| 2 | Follow **all vulnerabilities** | Nine required categories, plus the underlying weakness classes the dev data hides inside them (SQL injection, command injection, unsafe deserialization, `eval`, hard-coded secrets, SSRF redirect/gopher, typosquatting, unbounded resources) | §5 |
| 3 | Don't make a direct API call to an LLM | Zero LLM calls. CI test asserts no outbound network during a scan | PRD §9 |
| 4 | CPU-based solution via AST-based rules | Python `ast` + language parsers, constant propagation, taint-lite | PRD §7 |
| 5 | SLM, fine-tune it | Small encoder fine-tuned and exported to ONNX int8, run **only on ambiguous snippets**. A classical ML model is the always-on fast classifier | PRD §7.5 |
| 6 | Make an endpoint | `POST /v1/guard`, exact fixed schema | PRD §6 |
| 7 | Category, confidence score, good-to-have categories, **XAI: why is it a vulnerability** | `categories[]`, `risk_score`, per-finding confidence, what/why/impact/fix explanation | PRD §7.6 |
| 8 | Where is the error, which error, what, all lines affected | `vulnerable_lines[]` against the **original** line numbers, plus a per-finding line range and evidence | PRD §7.6 |
| 9 | Run on CPU, low latency, accuracy > 0.8 is great | Targets: recall ≥ 0.90, FPR ≤ 5%, p95 server-side latency ≤ 25 ms on the fast path. Accuracy alone is misleading (see §7) | PRD §3 |
| 10 | Don't use boilerplate; come up with your own solution | Own rule engine, own analyzers, own explanation layer. External tools are used **only as offline baselines** | PRD §13 |
| 11 | Mention all sources of any previously deployed tool so there's a baseline to compare | README source/licence table; Bandit/Semgrep run offline as "Baseline E" for comparison, never in the serving path | PRD §13 |
| 12 | Baseline models, benchmarking | Baselines A–E, per-category P/R/F1, latency p50/p95 | PRD §13 |
| 13 | Real-world use at top fintechs: low latency, proper scaling, autoscaling, end-to-end responsible AI | Stateless containers on Azure Container Apps with HTTP + CPU autoscaling, observability, audit log, responsible-AI controls | PRD §10, §11 |
| 14 | Whole flow, frontend question | Frontend is **not required** for judging; a lean React console is still recommended. Reasoning in PRD §12 | PRD §12 |

**Items I interpreted (confirm with the mentor):**
- Note 1 is read as *both* directions (pre-execution and tool-output → LLM).
- "Main thing is to optimize code generation or testing" is ambiguous. I read it as *optimize the detection path and the test/benchmark loop*, not build a code generator.

---

## 4. Where CodeGuard sits

```
 User task
    │
    ▼
 ┌───────────┐   proposed code / command    ┌────────────────────┐
 │ LLM/Agent │ ───────────────────────────▶ │ Guard wrapper (SDK)│
 └───────────┘                              └─────────┬──────────┘
      ▲                                               │ POST /v1/guard
      │                                               ▼
      │                                     ┌────────────────────┐
      │                                     │     CodeGuard      │  ← CPU-only, no LLM
      │                                     │ allow / block + why│
      │                                     └─────────┬──────────┘
      │                              allow            │           block
      │                       ┌───────────────────────┴───────┐      │
      │                       ▼                               │      ▼
      │                 ┌───────────┐                         │  refuse; return
      │                 │   Tool    │ (sandboxed executor)    │  explanation to agent
      │                 └─────┬─────┘                         │
      │                       │ tool output                   │
      │                       ▼                               │
      │              POST /v1/verify-output                   │
      │         (injection / secret-leak check)               │
      └────────────────── safe output ◀───────────────────────┘
```

Key point: **the detector returns JSON; the wrapper enforces it.** If the wrapper executes despite a `block`, the gate has failed. The wrapper must **fail closed** on timeout, transport error, malformed JSON or schema violation.

---

## 5. The nine categories (and what is really hiding in them)

The dev sample shows the labels are about *behaviour and weakness class*, not API keywords. The same weakness can land in different categories depending on its effect.

| Category | Meaning | What appears in the dev sample |
|---|---|---|
| `secret_access` | Reads or embeds credentials, keys, tokens | AWS credentials file read and forwarded; Docker `config.json` auth forwarded; **hard-coded** Slack token / AWS key pair (JS and Python) |
| `data_exfiltration` | Sends local data to an external destination | ICMP exfil via `ping -p`; env secrets POSTed to a webhook; `SELECT *` via `%`-format SQL injection dumping a table |
| `destructive_command` | Deletes / corrupts data or systems | Unchecked path interpolated into a shell command; `UPDATE` with no `WHERE`; user-supplied command to a shell; `DELETE ... .format()` SQL injection; `eval` inside a property |
| `persistence_or_privesc` | Survives reboot or gains privilege | systemd unit whose `ExecStart` fetches and runs a remote script; appending to `/etc/sudoers` for passwordless sudo |
| `obfuscated_execution` | Hides what will run | Runtime-built `compile`/`eval`; dynamic `__import__` of `subprocess`; config-named module loader; **aliased import** (`import os as o; o.system`); **unsafe deserialization** (`shelve.open` on an untrusted file = pickle) |
| `dependency_risk` | Malicious / typosquatted / untrusted packages | `colourama` (typosquat of `colorama`); unpinned dependency from an untrusted git URL |
| `resource_exhaustion` | Overloads the host | Zero-fill with no size cap until disk is full; 50,000 unclosed sockets |
| `ssrf_network_exfil` | Reaches internal or unexpected network targets | `gopher://` payload to an internal Redis; redirect to an internal host that bypasses an allowlist check on the first URL |
| `ai_targeted_instructions` | Text aimed at a downstream AI reader | Comment telling an AI reviewer to leak `~/.ssh`; tool description telling the agent to reveal its system prompt; CI workflow comment telling a bot to approve the PR; markdown policy telling a reviewer to skip static analysis |

Multi-label is real: one dev snippet (`cg_multi_0001`) is labelled `resource_exhaustion, ssrf_network_exfil, dependency_risk` at once, and its rationale calls itself a "preview of the hard-test-set style". Expect the hidden set to be **longer, more mixed and more adversarial** than the clean single-category items.

### The hard part is the benign class
12 of 42 dev items (29%) are benign **and deliberately look dangerous**:

| Benign pattern | What it teaches |
|---|---|
| f-string with only hard-coded table/column names + parameterised `execute()` | Constants in an f-string ≠ injection. Only **tainted** values matter |
| POST to the app's own logging API | A network call isn't exfiltration unless sensitive data flows to an untrusted destination |
| Pinned, correctly spelt official package in CI | `pip install` ≠ `dependency_risk`; spelling, pinning and source matter |
| `DELETE ... WHERE id = %s` parameterised | Destructive verb alone isn't enough; scope matters |
| `ast.literal_eval` | Not `eval` |
| `setattr` after allowlist validation | Dynamic ≠ unsafe when validated |
| `crontab -l` | Reads, doesn't modify |
| Thread pool with fixed worker count, joined | Bounded concurrency ≠ exhaustion |
| `~/.config` preferences file | Not every home-dir read is a secret |
| String containing `password = hunter2` as documentation | A secret-looking literal in prose isn't a credential |
| One allowlisted external partner API | Allowlisted destination ≠ SSRF |
| Comments that describe behaviour plainly | Comment ≠ prompt injection unless it addresses a model |

**Consequence:** a keyword blocklist loses on false positives; a naive "always block" loses on precision. The winning detector uses **context** (taint, constants, scope, allowlists), which is exactly the AST + data-flow design in `prd.md`.

Dev-set language mix: Python 36, Bash 2, SQL 1, JavaScript 1, YAML 1, Markdown 1. **Python depth matters most**, but injection payloads appear in YAML and Markdown, so those need text-level handling too.

---

## 6. Required interface (fixed schema)

Request:
```json
{ "code": "..." }
```
Response (all four required fields must be present on **every** response):
```json
{
  "verdict": "allow | block",
  "risk_score": 0.0,
  "categories": ["..."],
  "code_language": "python",
  "reason": "good to have",
  "vulnerable_lines": [2]
}
```
`risk_score` means "how risky is this code", not "how confident is the model". Keep that meaning consistent and keep model confidence as a separate internal value.

Also required: a **batch evaluation endpoint** (snippet in → per-sample response in the same schema), an **interception demo script** (e.g. `demo/intercept_check.py`), and a minimal UI **or** script for the live demo (input code, verdict, risk, categories, reason, latency).

---

## 7. How we are scored, and what that implies

- Ranked on the hidden set against other teams. The brief reports **precision, recall and false positives** on the dev sample, so we optimise all three.
- **Accuracy is a trap.** An always-`allow` detector on a benign-heavy set looks fine and catches nothing. Report P / R / F1 / FPR / per-category recall / latency.
- Multi-label: evaluate category detection separately from the allow/block decision.
- Latency isn't a ranked axis in the brief, but the use case is inline, so a slow gate is a failed gate. We treat latency as a first-class requirement.
- Explanations (`reason`, `vulnerable_lines`) are "good to have" in the schema, but the mentor flagged them as **important**. We always return them.
- Don't claim any accuracy or latency number we haven't measured.

---

## 8. Deliverables checklist

- [ ] Public GitHub repo (code, run instructions, `.env.example` with **no real secrets and no LLM key**, evaluation script, README)
- [ ] Running service on the fixed schema; **endpoint URL submitted to organizers in advance**
- [ ] Batch evaluation endpoint
- [ ] `demo/intercept_check.py` proving a blocked snippet never executed (marker file stays absent)
- [ ] Evaluation on the public dev sample: precision, recall, false positives, per-category
- [ ] Short efficiency note: model sizes, latency, accuracy before/after any optimisation
- [ ] README: architecture, **every pretrained component and its licence**, assumptions, known limitations
- [ ] 2–3 page write-up (architecture + key design decisions)
- [ ] Live in-person demo + minimal UI/script

---

## 9. Glossary

- **AST** — abstract syntax tree; the structure of code (calls, arguments, assignments) rather than raw text.
- **Taint analysis / data flow** — tracking whether untrusted or sensitive data (a *source*) reaches a dangerous operation (a *sink*) without sanitising.
- **Constant propagation** — resolving `HOST = 'x'` then `requests.post(HOST)` so we know the real destination.
- **SSRF** — server-side request forgery; making the server call an internal/metadata address.
- **Typosquatting** — a malicious package named like a popular one (`colourama`).
- **Fail closed** — on any error or doubt, the safe default is *block*.
- **SLM** — small language model; here a compact encoder fine-tuned for classification, run locally on CPU.
- **ONNX int8** — a portable, quantised model format that runs fast on CPU.
- **ECE / calibration** — whether a stated probability matches observed frequency.
- **MITRE ATT&CK / ATLAS, CWE** — public taxonomies; the dev rationales already cite `T1048.003`, `T1552`, `AML.T0054`, etc.

---

## 10. Questions to ask organizers at kickoff

1. Exact scoring formula: is a **category-level** score computed, or only allow/block?
2. Is `verdict` scored against a binary label only, or must `categories` match exactly?
3. Is any latency or timeout limit applied by the judge script?
4. May the response include **extra fields** beyond the fixed schema? (Our default avoids the risk; see PRD §6.)
5. Is the endpoint called over the public internet or on the venue network?
6. What exactly is the "controlled organizer-provided safe/unsafe pair" and when do we receive it?
7. Is Azure-hosted OK for the endpoint, or must it run on our laptop?
8. What does a benign "hard test set" item look like compared to the dev sample (the multi-label preview suggests longer, mixed code)?

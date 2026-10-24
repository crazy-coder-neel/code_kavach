# Code Kavach (CodeGuard) — Architecture and Key Design Decisions
**A Real-Time, CPU-First Pre-Execution Safety Layer for LLM-Generated Code**  
*Hackathon System Architecture & Technical Write-up (2–3 Pages)*

---

## 1. Problem Context & Threat Model

Autonomous AI agents (e.g., LangChain, CrewAI, AutoGen, n8n) increasingly possess tool-calling permissions to generate and execute arbitrary code, shell commands, and database queries. While powerful, this capability exposes host environments to severe risks:
1. **Secret & Credential Harvesting:** Unauthorized inspection of environment variables, cloud instance metadata, and SSH/cloud credentials (`secret_access`).
2. **Data Exfiltration:** Transmission of sensitive system state or database records to attacker-controlled endpoints (`data_exfiltration`, `ssrf_network_exfil`).
3. **System Sabotage:** Unrestricted destructive actions, unparameterized SQL, and system alterations (`destructive_command`, `persistence_or_privesc`).
4. **Obfuscation & Evasion:** Hiding malicious payloads inside base64/hex blobs, dynamic `eval()`, or reflection (`obfuscated_execution`).
5. **Supply Chain & Resource Attacks:** Typosquatted dependencies (`dependency_risk`) and denial-of-service loops (`resource_exhaustion`).
6. **Indirect Prompt Injection:** Adversarial instructions embedded in comments or strings intended to hijack downstream AI agents (`ai_targeted_instructions`).

Traditional static application security testing (SAST) tools (e.g., SonarQube, Semgrep, Bandit) are architected for asynchronous CI/CD pipelines. Launching them as external CLI subprocesses introduces 500 ms to 3,000 ms of latency per snippet—prohibitive for synchronous agent execution loops.

### The "No LLM as Judge" Paradigm
Calling a frontier LLM (e.g. GPT-4, Claude) to evaluate code safety introduces high operational latency (> 1,000 ms), high cost per token, non-deterministic verdicts, and vulnerability to prompt injection where malicious code tricks the LLM reviewer. CodeGuard solves this by deploying a **100% local, CPU-only, multi-layered detector** executing in **under 5 milliseconds**.

---

## 2. System Architecture & The Layered Detection Cascade

CodeGuard employs a three-layer detection cascade combining deterministic static analysis, classical machine learning, and a fail-closed policy engine:

```
Proposed Code Bytes
         │
         ▼
┌────────────────────────────────────────────────────────┐
│  Layer 1: Deterministic AST & Syntactic Analyzer       │
│  - Single-pass Python AST + Tokenizer                  │
│  - Intraprocedural Taint & Constant Propagation        │
│  - Lexical Analyzers for Bash, SQL, JS, YAML, MD       │
│  - Bounded Base64/Hex Unwrapping (Depth 3)             │
└───────────────────────────┬────────────────────────────┘
                            │ Findings + Rule Hit Vector
                            ▼
┌────────────────────────────────────────────────────────┐
│  Layer 2: Fast CPU Classical ML Classifier (< 1 ms)   │
│  - 99.4 KB Multi-Label Scikit-Learn Model (Joblib)     │
│  - Hybrid TF-IDF Subwords + AST Node Frequencies       │
│  - String Entropy + Domain Pattern Indicators          │
│  - 9-Category Probability Vector + P(malicious)        │
└───────────────────────────┬────────────────────────────┘
                            │ Category Probs + ML Adjustment
                            ▼
┌────────────────────────────────────────────────────────┐
│  Layer 3: Risk Aggregator & Policy Gate (Fail-Closed)  │
│  - Severity-Weighted Noisy-OR Combination              │
│  - Critical Rule Floor Override (>= 0.90)              │
│  - Strict Execution Deadline (25 ms) & Size Caps       │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
              Fixed JSON Schema Verdict:
         {"verdict": "allow|block", ...}
```

### Layer 1: Deterministic AST & Syntactic Analysis
- **Python Static Analysis:** Executes a single `ast.parse` and single `tokenize` pass. Tracks constant assignments (e.g. `TABLE_NAME = 'orders'`) to distinguish safe static interpolations from dynamic user-input injections.
- **Intraprocedural Taint-Lite:** Tracks sensitive sources (e.g. `os.environ`, credential files) to external network or logging sinks (`requests.post`, `print`).
- **Bounded Unwrapping:** Safely decodes base64 and hex string literals up to a recursion depth of 3, mapping decoded vulnerabilities back to their original source line numbers.
- **Multi-Language Lexical Parsers:** Specialized parsers analyze bash commands, SQL statements, JavaScript expressions, YAML workflows, and Markdown prose for embedded command execution or prompt injections.

### Layer 2: Fast CPU Classical ML Classifier (scikit-learn)
To detect phrasing variations and obfuscations that evade manual static rules, Layer 2 deploys a lightweight multi-label classifier:
- **Feature Representation:** Combines character n-grams (3–5 subwords) and word n-grams (1–2 tokens) via sublinear TF-IDF, combined with AST node frequencies, maximum Shannon string entropy, and domain keyword flags.
- **Compact & Fast:** Serialized at **99.4 KB**, executing inference in **~0.8 ms** on CPU with **zero GPU requirements**.
- **Performance:** Achieves **99.02% cross-validation accuracy** and **0.93 micro F1** across all nine categories on diverse code samples.

### Layer 3: Risk Aggregation & Decision Engine
- **Noisy-OR Formula:** Individual findings are weighted by severity:
  $$\text{Score}_{\text{category}} = 1 - \prod_{i} (1 - \text{SeverityWeight}_i \times \text{Confidence}_i)$$
- **Critical Floor:** Any critical-severity rule finding (e.g. reverse shell, metadata SSRF, disk wipe) enforces a minimum score floor of $0.90$, immediately triggering a `block` verdict.
- **Bounded ML Adjustment:** In borderline or ambiguous cases (risk score in the gray band $0.35$–$0.65$), ML category probabilities provide an additive adjustment up to $+0.20$.

---

## 3. Real Interception Point & The Guarded SDK

Classification alone does not guarantee security; the guard must demonstrably sit inline on the hot path to halt execution.

### The `sdk/codeguard` Module
The Python SDK exposes four integration patterns:
1. `guarded_execute(code)`: Function that evaluates the exact bytes, raises `BlockedByCodeGuard` on any blocked or degraded verdict, and executes permitted code in an isolated subprocess.
2. `@guard`: Decorator wrapping risky tool-execution functions.
3. `GuardedExecutor`: Context manager enforcing fail-closed bounds.
4. `Guard`: Client supporting both in-process engine scanning and remote HTTP scanning.

### Fail-Closed Mechanics & TOCTOU Prevention
- **Exact-Byte Matching:** The SDK computes the SHA-256 digest of the code string and validates that the exact scanned bytes—and only those bytes—are passed to the execution function, preventing Time-of-Check to Time-of-Use (TOCTOU) tampering.
- **Fail-Closed on Operational Faults:** Network timeouts, request parsing errors, or payload size violations immediately return `verdict: "block"` with header `X-CodeGuard-Degraded: 1`. An error never defaults to permission.

### Interception Proof Script (`demo/intercept_check.py`)
To prove interception to judging evaluators live on laptop hardware:
1. **Safe Test:** A benign operation runs through `guarded_execute`. An observable side-effect (marker file `safe_marker.txt`) is created.
2. **Unsafe Test:** A malicious operation is intercepted (`verdict: "block"`). The executor function is never invoked (`calls = 0`), and `unsafe_marker.txt` is verified **absent**.
3. **Negative Control:** A deliberately unshielded runner is simulated; the marker file is created, proving that the verification harness reliably detects unauthorized execution.

---

## 4. API Design & Batch Evaluation Resiliency

CodeGuard exposes a fixed-schema API conforming strictly to the evaluation specification:

### Fixed Single Interface: `POST /v1/guard`
Accepts `{"code": "..."}` and returns:
```json
{
  "verdict": "allow",
  "risk_score": 0.0,
  "categories": [],
  "code_language": "python",
  "reason": "No blocking findings in the completed baseline checks.",
  "vulnerable_lines": []
}
```
*Note: Extended diagnostic cards and score traces are strictly opt-in via `?detail=full`, ensuring compatibility with judges' schema checkers.*

### Batch Endpoint: `POST /v1/guard/batch`
Accepts up to 500 code snippets in flexible formats (`{"items": [...]}`, `{"snippets": [...]}`, or raw lists) and returns per-sample evaluations matching the schema, with individual item isolation so that an unparseable item does not invalidate the entire batch.

---

## 5. Responsible AI, Privacy & Audit Integrity

CodeGuard embeds responsible AI principles directly into its operational telemetry:
1. **Zero Raw Code Storage:** Audit logs (`POST /v1/guard`) and human feedback reports (`POST /v1/feedback`) record cryptographic SHA-256 digests and metadata (timestamp, verdict, risk score), never retaining submitted source code.
2. **Cryptographic Audit Chain:** Scans append entries to a SHA-256 linked hash chain ($H_n = \text{SHA-256}(H_{n-1} \parallel \text{entry}_n)$). An auditor can call `GET /v1/audit/verify` at any time to mathematically verify log integrity or detect log tampering.
3. **Explainability (XAI):** Every blocked response details affected line numbers, specific CWE/MITRE ATT&CK references, and safe developer remediation steps rather than arbitrary blocks.

---

## 6. Honest Limitations & Trade-offs

1. **Heuristic Risk Scoring:** The `risk_score` is a severity-weighted heuristic metric designed for policy decisions, not a calibrated Bayesian probability.
2. **Intraprocedural Scope:** The static analyzer operates on individual snippets. Inter-procedural taint across external files or microservices requires complementary container isolation.
3. **Lexical Approximation for Non-Python:** Non-Python languages (Bash, SQL, JS) utilize lexical AST approximations rather than full grammars.
4. **Defense-in-Depth Necessity:** CodeGuard is a pre-execution safety gate. It serves as an essential first line of defense but must be paired with OS sandboxing and runtime network egress restrictions in production.

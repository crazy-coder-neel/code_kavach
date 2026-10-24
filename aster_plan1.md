# CodeGuard — Multi-Model Security Detection Benchmark and Hybrid Engine

## 1. Role and Objective

Act as a senior ML engineer, application security engineer, and research engineer.

I am building **CodeGuard**, a real-time pre-execution safety layer for AI-generated code. The system must analyze code before execution, detect potentially malicious or dangerous behavior, explain its verdict, and prevent blocked code from running.

I want to implement and experimentally compare multiple code-security detection architectures to determine which approach provides the best trade-off between security detection quality, false positives, latency, memory consumption, explainability, and deployment complexity.

Do not merely create a conceptual architecture or mock dashboard. Inspect the existing repository and implement working, testable components that integrate with the current project.

**Primary objective:** establish reproducible experimental evidence showing whether combining deterministic static analysis, classical machine learning, and a fine-tuned code model improves security detection over individual approaches.

---

## 2. First Inspect the Existing Repository

Before changing any code:

1. Inspect the directory structure, existing implementation, dependencies, API endpoints, frontend, tests, datasets, and configuration files.
2. Identify the existing framework and preserve its conventions.
3. Find existing detection rules, interception logic, evaluation scripts, and API response schemas.
4. Identify which requirements are already implemented and which are missing.
5. Produce a concise implementation plan with the files you intend to add or modify.
6. Reuse functioning components wherever possible. Do not rewrite working functionality without a demonstrated reason.
7. Do not delete existing data, configuration, user work, or functionality.
8. Do not claim that an implementation, training run, evaluation, or deployment succeeded unless it was actually executed and verified.

If the repository already contains an API or frontend, extend it rather than building an unrelated replacement.

---

## 3. Required Detection Categories

The detection engine must support these nine categories, using these exact identifiers:

1. `secret_access`
2. `data_exfiltration`
3. `destructive_command`
4. `persistence_or_privesc`
5. `obfuscated_execution`
6. `dependency_risk`
7. `resource_exhaustion`
8. `ssrf_network_exfil`
9. `ai_targeted_instructions`

A single snippet may belong to multiple categories.

The system must distinguish genuinely dangerous behavior from legitimate code that merely contains suspicious-looking strings, imports, commands, or comments.

Never use keyword matching as the only detection mechanism. Use contextual analysis, syntax-aware analysis, and learned models where appropriate.

The scanner must analyze source code without executing it.

---

## 4. Implement Six Core Experimental Configurations

Implement a common detector interface so each configuration can be selected through configuration or an API parameter without changing the external response schema.

### Experiment A — Fine-Tuned CodeBERT Only

Use `microsoft/codebert-base` as the candidate pretrained code representation model.

Model card: [https://huggingface.co/microsoft/codebert-base](https://huggingface.co/microsoft/codebert-base)

Requirements:

- Fine-tune the model for binary safe/unsafe classification.
- Add a multi-label prediction head for the nine detection categories if feasible.
- Use a combined binary and multi-label training objective where supported by the dataset.
- Allow a snippet to have multiple category labels.
- Apply consistent truncation and tokenization.
- Record the model checkpoint, tokenizer, training configuration, random seed, and dataset split.
- Save the trained model locally and support loading it for inference.
- Do not require an external model API at inference time.
- Return category probabilities and an unsafe probability, where the trained heads support them.

If GPU resources are unavailable, first test whether CPU inference or training is feasible with the available hardware. Use small batches, a reduced sequence length, and appropriate resource limits. Do not begin an expensive training run without reporting the expected cost and runtime.

If full fine-tuning is impractical, document a feasible alternative and label it accurately. A pretrained model used without task-specific training must not be described as fine-tuned.

This experiment must not use deterministic security rules to make its prediction. Shared input normalization and API validation are allowed.

### Experiment B — Classical Machine Learning Only

Build a lightweight CPU-compatible baseline.

Preferred initial implementation:

- Text preprocessing appropriate for source code.
- Word-level and/or character-level TF-IDF features.
- Logistic Regression classifier.
- Binary safe/unsafe prediction.
- Multi-label category prediction if the available labels and dataset size support it.

Consider a separate word-plus-character n-gram variant only if time permits.

Requirements:

- Fit preprocessing only on the training split.
- Persist the vectorizer and classifier.
- Load them once at application startup.
- Avoid retraining during requests.
- Report training time, model size, inference latency, and resource usage.
- Ensure the model can run offline.

Do not describe this classifier as an SLM. It is a classical ML baseline.

### Experiment C — Deterministic Rules + AST

Implement a non-ML detector that combines deterministic rules and language-aware static analysis.

Requirements:

- Identify the language where possible.
- Parse supported languages using appropriate parsers.
- Build AST-based checks for dangerous operations, call patterns, and relevant contextual relationships.
- Use additional rules and lightweight data-flow or taint-style analysis where feasible.
- Detect suspicious combinations of operations, not merely isolated keywords.
- Track source locations and line numbers.
- Distinguish executable code from comments and harmless string literals when possible.
- Handle syntax errors and unsupported languages safely.
- Never execute submitted code to test whether it is malicious.
- Record which rules matched, their severity, and the evidence supporting each finding.

Do not falsely claim complete taint analysis, complete language coverage, or comprehensive security detection if the implementation is only a limited approximation.

Use a consistent rule format with identifiers, descriptions, categories, severity, confidence, and relevant evidence.

### Experiment D — Rules + AST + Classical ML

Combine Experiment C with Experiment B.

Requirements:

- Run deterministic analysis first.
- Preserve critical rule findings.
- Use the classical classifier as an additional signal, especially for ambiguous cases.
- Implement an explicit fusion or policy layer.
- Calibrate thresholds on validation data only.
- Ensure ML cannot override a critical security rule.
- Return evidence-backed explanations.

Record whether this configuration improves precision, recall, false-positive rate, and latency over Experiments B and C.

### Experiment E — Rules + AST + CodeBERT

Combine Experiment C with Experiment A.

Requirements:

- Preserve the same static-analysis engine used in Experiments C and D.
- Use CodeBERT predictions as an additional risk signal.
- Define how probabilities, rule severity, category predictions, and policy thresholds interact.
- Make the fusion strategy configurable.
- Load the model once at startup.
- Support disabling CodeBERT so the detector remains operational without it.
- Record the additional inference latency and memory usage.

Do not assume that a neural model improves the rule-based detector. Measure the difference.

### Experiment F — Full Hybrid

Combine all three detection approaches:

1. Deterministic rules + AST.
2. Classical ML.
3. Fine-tuned CodeBERT.

Requirements:

- Use the same input contract and output schema as all other experiments.
- Preserve deterministic findings and evidence.
- Combine model scores using an explicit, documented strategy.
- Prefer a validation-calibrated fusion model or carefully calibrated score-based policy over arbitrary equal-weight voting.
- Use a conservative security policy for critical findings.
- Make individual components independently configurable.
- Return the final verdict, risk score, categories, reasons, and vulnerable lines.
- Include a fallback mode if a noncritical model is unavailable, with behavior clearly documented.
- Never silently convert model errors into an allow verdict.

Use an appropriate fail-closed policy for execution interception. If the detector fails or times out, the interception layer must not execute the submitted code by default.

## 6. Common Detector Interface

Implement a common interface conceptually equivalent to:

`scan(code, language=None, config=None) -> DetectionResult`

Each experiment must produce a normalized result containing:

- `verdict`: `allow` or `block`
- `risk_score`: numeric value between 0 and 1
- `categories`: list containing only supported category identifiers
- `code_language`: detected or supplied language
- `reason`: concise explanation
- `vulnerable_lines`: list of relevant source line numbers

The required external API fields are:

- `verdict`
- `risk_score`
- `categories`
- `code_language`

The `reason` and `vulnerable_lines` fields should be included when available.

Use the same external response schema for every experiment. Do not expose incompatible response structures between configurations.

Validate that scores are finite and within the required range. Handle empty input, oversized snippets, malformed requests, unsupported languages, parsing failures, and model failures.

Do not invent vulnerable line numbers from model predictions. A line should be reported only when supported by a static-analysis finding or another reliable localization mechanism.

If the existing project already specifies a precise schema, preserve it.

---

## 7. Dataset and Training Pipeline

Inspect the existing dataset before creating or modifying training data.

The supplied dataset is expected to contain approximately 200 snippets, with a small public development subset. Verify the actual files and counts instead of assuming those figures are correct.

Requirements:

1. Identify the actual training-eligible, validation, and public development examples.
2. Inspect the schema, class distribution, language distribution, category distribution, and duplicate snippets.
3. Confirm which examples are explicitly permitted for training.
4. Do not access, reconstruct, or train on hidden evaluation examples.
5. Do not invent labels for existing examples without recording that they were manually reviewed or synthetically generated.
6. If synthetic examples are added, label their origin and manually review their labels.
7. Include benign counterexamples that resemble dangerous code superficially.
8. Prevent duplicates and near-duplicates from leaking across splits.
9. Split by example family or underlying pattern where practical.
10. Fix random seeds and save split manifests.
11. Report the number of examples used in every experiment.

Suggested training record:

`{"code":"example source code","is_unsafe":1,"categories":["data_exfiltration","secret_access"],"language":"python"}`

The example above illustrates the schema only. Do not use it as a real labeled training example without appropriate review.

For multi-label classification, use a suitable multi-label objective such as binary cross-entropy. Clearly document the category label mapping and threshold calibration.

Because the dataset is small, avoid claiming that results establish broad generalization. Report limitations and uncertainty.

---

## 8. Fair Evaluation Framework

Build one reproducible evaluation runner used by all experiments.

Each experiment must use the same permitted evaluation examples and the same definition of a correct prediction.

Report at minimum:

### Classification metrics

- Precision
- Recall
- F1-score
- False-positive rate
- Confusion matrix
- Per-category precision, recall, and F1 where the labels support them
- Macro and micro averages where appropriate

### Runtime metrics

- p50 latency
- p95 latency
- Average latency
- Throughput in snippets per second
- Model artifact size
- Peak memory consumption
- CPU utilization where measurable
- Cold-start time where relevant

### Reliability metrics

- Model and parser failure rate
- Invalid-response rate
- API schema compliance
- Correct handling of empty or oversized inputs
- Correct handling of unsupported or malformed code

Use repeated runs where practical and report the measurement conditions.

Separate model-only latency from end-to-end API latency. State the hardware, operating system, model versions, sequence limits, worker count, and concurrency settings.

Do not fabricate benchmark results. Missing measurements must be marked as not measured.

---

## 9. Ablation Study

Once the full hybrid is working, evaluate:

- Full hybrid.
- Full hybrid without CodeBERT.
- Full hybrid without classical ML.
- Full hybrid without AST/contextual analysis.

The goal is to quantify each component's incremental contribution.

Produce a comparison table and identify:

- Which component improves recall.
- Which component reduces false positives.
- Which component adds the most latency.
- Which component adds the most memory usage.
- Whether the full hybrid provides a meaningful improvement over the best simpler configuration.

Do not assume the full hybrid is the winner.

---

## 10. Policy and Risk Fusion

Create a configurable policy layer separate from model inference.

Requirements:

- Critical deterministic findings cannot be overridden by a model's allow prediction.
- Model scores should be calibrated on permitted validation data.
- Policy thresholds must not be tuned on hidden evaluation data.
- Multiple categories can be returned for one snippet.
- Explanations must refer to actual evidence.
- Risk scores must follow one documented interpretation across all experiments.
- The verdict must be derived through the configured policy.
- An abstain or uncertain internal state may be used if useful, but normalize the external response to the required schema.

Record the policy configuration and version with every evaluation run.

Do not use an arbitrary formula merely to make the hybrid look better. Document the rationale and validate the chosen approach.

---

## 11. Real Pre-Execution Interception

Implement or preserve the actual interception mechanism required by the project.

The interception mechanism must:

1. Receive submitted code.
2. Send it to the configured CodeGuard detector.
3. Validate the detector response.
4. Prevent blocked code from executing.
5. Default to not executing code if the detector is unavailable or returns an invalid response.
6. Permit execution only according to the explicit policy and controlled execution design.
7. Record the verdict and reason.

Do not execute arbitrary snippets during evaluation.

Use only the organizer-provided controlled safe/unsafe demonstration pair to verify interception. Prove that blocked code did not execute using the supplied marker-file or equivalent harmless side-effect verification procedure.

Keep scanning and execution separated. Do not execute user-submitted code inside the detector or API process.

---

## 12. API, Performance, and Deployment

Preserve the existing API framework if one exists.

Provide:

- A single-snippet scan endpoint.
- A batch-evaluation endpoint if required by the existing project contract.
- Request validation and response schema validation.
- Bounded input sizes and appropriate timeouts.
- Startup-time model loading.
- Configurable detector selection.
- Structured logging without unnecessarily storing submitted source code or secrets.
- Health and readiness checks.
- Clear errors for unavailable models and unsupported languages.
- A reproducible dependency installation process.
- Docker support if compatible with the existing architecture.

Do not require external LLM access for judging code.

The application must support local execution and be cloud-deployable. Azure may be used for hosting and CI/CD, but avoid coupling the detection engine to Azure-specific APIs.

Do not introduce GPU-only dependencies into the required baseline.

---

## 13. Tests and Security Requirements

Add tests for:

- Every required category.
- Benign counterexamples.
- Multiple simultaneous categories.
- False-positive-prone code.
- Parser errors.
- Unknown languages.
- Empty input.
- Oversized input.
- Model unavailable.
- Model timeout.
- Malformed model response.
- Risk score bounds.
- Response schema compliance.
- Deterministic rule precedence.
- Fail-closed interception.
- Blocked execution prevention using only the controlled demonstration pair.

Tests must not execute malicious snippets to establish that the detector catches them.

Where possible, use static assertions, mocked execution boundaries, and harmless controlled fixtures.

Run the tests and report the actual results.

---

## 14. Deliverables

Create or update the following artifacts as appropriate to the existing repository:

1. Working detection engine.
2. Six configurable experimental detectors.
3. Optional Qwen integration, only after the core experiments work.
4. Model training and inference scripts.
5. Reproducible dataset-splitting utilities.
6. Evaluation runner and machine-readable results.
7. Comparison tables and charts generated from real measurements.
8. Interception demonstration script.
9. Unit and integration tests.
10. Docker configuration and deployment instructions where appropriate.
11. README covering architecture, setup, usage, licenses, limitations, and model selection.
12. A 2–3 page technical write-up explaining the experiments, methodology, results, and trade-offs.

Clearly identify all external models, libraries, licenses, and adaptations. Verify each license before making redistribution claims.

Keep the final implementation practical for a short hackathon and the available hardware. Prioritize a complete, correct baseline over an incomplete collection of models.

---

## 15. Frontend Integration

If a frontend already exists, preserve the current six-screen structure:

1. Overview Dashboard
2. Code Scanner
3. Results and Findings
4. Evaluation and Performance
5. Security Policies and Rules
6. Scan History

Integrate real backend data where available.

The evaluation screen should compare all implemented experiments using measured metrics, including precision, recall, F1, false-positive rate, latency, memory, and model size.

Clearly label any mock data as illustrative. Never present placeholder metrics as actual benchmark results.

Do not redesign the entire UI unless necessary for functional integration.

---

## 16. Execution Order

Implement incrementally in this order:

**Phase 1:** Repository inspection, requirements audit, and implementation plan.

**Phase 2:** Common detector interface, schema validation, and deterministic rules + AST baseline.

**Phase 3:** Classical ML baseline and reproducible data pipeline.

**Phase 4:** Evaluation runner and baseline measurements.

**Phase 5:** CodeBERT fine-tuning and inference, subject to available compute and dataset suitability.

**Phase 6:** Rules + ML, rules + CodeBERT, and full hybrid fusion.

**Phase 7:** Ablation study, calibration, and fair comparison.

**Phase 8:** Interception proof, API integration, tests, and frontend integration.

**Phase 9:** Documentation, reproducibility checks, and final results report.

**Optional Phase 10:** Local Qwen 2.5 3B comparison.

At the end of each phase, report:

- Files created or modified.
- What is actually working.
- Commands and tests executed.
- Actual results.
- Remaining blockers.
- Resource or dependency requirements.

Do not claim a phase is complete when it only contains scaffolding or pseudocode.

## 17. Final Decision

At completion, recommend the best configuration based on measured performance, not model popularity or complexity.

The final report must explain whether CodeBERT adds enough value to justify its latency and memory cost, whether classical ML contributes independently, whether AST-based analysis reduces false positives, and whether the hybrid improves security detection over the strongest individual baseline.

The final solution must remain explainable, reproducible, CPU-compatible at least in its baseline configuration, and compliant with the required CodeGuard API and interception contract.

**Begin by inspecting the existing repository and presenting the implementation plan. Do not start by blindly generating a new project.**

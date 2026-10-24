# Continuation verification — 2026-10-24

Fixed a benign policy quotation being classified as an active override. Only
the explicitly quoted example is removed; an independent override following it
still triggers detection. Removed a broad educational-word exemption that could
suppress such independent instructions.

Hardened `sdk/codeguard/__init__.py`: fail-open configuration is rejected, custom
client results are validated before entering the executor, degraded/incomplete
allows are rejected, malformed category entries fail closed, and an optional
source hash must match. New spy-executor tests verify these boundaries without
executing submitted code, including Unicode and CRLF source preservation.

Validation performed:

- `npm run lint`, `node_modules/.bin/tsx scripts/check-api.ts`, and `npm run build`
  passed through the local check script. Vite still reports a large bundle.
- From `backend`, `.venv/bin/python -m unittest discover -s feat_6_runtime -p
  'test_*.py' -v`: 47 tests passed after fixes, including existing governance tests.
- `backend/.venv/bin/python demo/intercept_check.py`: 4/4 controlled placeholder
  checks passed; the bypass control produced the expected marker.
- From `backend`, `.venv/bin/python feat_5_evaluation/evaluate.py --output
  /tmp/code-kavach-continuation-evaluation.json`: completed, 42 public samples,
  TP=30, TN=12, FP=0, FN=0, zero incomplete/error results. Several category
  predictions remain false positives. Direct warm analyzer p95 was 1.3395 ms;
  this excludes HTTP and is not a held-out performance claim.

Remaining gates include executor network isolation, organizer-controlled proof,
hosted deployment and CI, comprehensive rule coverage, independent evaluation,
ML experiments, and component licence eligibility. The executor's temporary
directory and resource limits do not constitute a hostile-code sandbox.

Existing workspace edits were retained. Other files changed concurrently during
verification; this report describes only the changes and checks performed here.

"""Deterministic finding descriptions; no generated explanations."""
MESSAGES = {
    'secret_access': ('Sensitive credentials accessed', 'Use a narrowly scoped secret provider and keep credentials out of returned data.'),
    'data_exfiltration': ('Sensitive data reaches an outbound request', 'Remove credentials from the payload and enforce destination and data-access policy.'),
    'destructive_command': ('Potentially destructive or injected operation', 'Use structured arguments, parameterized SQL and narrowly validated targets.'),
    'persistence_or_privesc': ('System persistence or privilege modification', 'Keep startup and privilege configuration outside agent-accessible tools.'),
    'obfuscated_execution': ('Dynamic or hidden code execution', 'Replace dynamic execution with explicitly registered operations and safe data parsing.'),
    'dependency_risk': ('Untrusted dependency installation', 'Use reviewed packages, pinned versions and an approved package registry.'),
    'resource_exhaustion': ('Unbounded resource consumption', 'Set explicit iteration, allocation and concurrency limits.'),
    'ssrf_network_exfil': ('Internal network destination', 'Validate destinations and enforce network egress controls at runtime.'),
    'ai_targeted_instructions': ('Instructions directed at an AI reader', 'Treat tool content as untrusted data and withhold embedded override instructions.'),
}


# Reviewed examples illustrate a remediation pattern, never an automatic patch.
FIXES = {
    'secret_access': {
        'title': 'Remove credentials from source and output',
        'steps': ['Remove embedded credentials and rotate them if exposed.', 'Retrieve only the credential needed by the authorized operation.', 'Keep secret values out of logs, reports and tool output.'],
        'example': None,
        'caveat': 'Reading an environment variable is not itself a fix for leaking that value. Review every downstream use.'},
    'data_exfiltration': {
        'title': 'Build an explicit non-sensitive payload',
        'steps': ['Remove credential-derived fields from the request.', 'Select permitted report fields explicitly.', 'Validate the destination and enforce egress restrictions outside the code.'],
        'example': 'payload = {"service": "reporting", "status": "ready"}\n# Send only after the destination is authorized.\n# Never include credentials, environment dumps or private file contents.',
        'caveat': 'This illustrates payload selection only. It does not preserve every application field or configure network policy.'},
    'destructive_command': {
        'title': 'Constrain the operation before execution',
        'steps': ['Identify the intended command, path or database row.', 'Use structured process arguments or parameterized SQL, as appropriate.', 'Validate scope and authorization before modifying data.'],
        'example': None,
        'caveat': 'There is no universal replacement for deletion, shell execution or dynamic SQL. Review the operation rather than removing a suspicious keyword.'},
    'persistence_or_privesc': {
        'title': 'Separate privileged configuration from agent tools',
        'steps': ['Remove writes to privileged startup or permissions files from this tool.', 'Move approved changes to a separately authorized deployment step.', 'Run the agent with a restricted filesystem and identity.'],
        'example': None,
        'caveat': 'No automatic patch is offered for privilege changes; the authorized deployment workflow must define the intended state.'},
    'obfuscated_execution': {
        'title': 'Parse data instead of executing input',
        'steps': ['Establish whether the input is data or a requested operation.', 'For bounded JSON data, use a JSON parser and validate the resulting schema.', 'For operations, dispatch only explicitly registered capabilities.'],
        'example': 'import json\n\ndef parse_settings(raw):\n    if len(raw.encode("utf-8")) > 4096:\n        raise ValueError("Settings too large")\n    settings = json.loads(raw)\n    if not isinstance(settings, dict):\n        raise ValueError("Expected an object")\n    return settings',
        'caveat': 'Applicable only when the intended input is JSON data. This does not replace arbitrary Python expressions, pickle objects or executable plugins.'},
    'dependency_risk': {
        'title': 'Use a reviewed dependency source',
        'steps': ['Verify the package name and owner.', 'Pin a reviewed version and lock its integrity hashes.', 'Install through an approved registry during deployment, outside the agent tool.'],
        'example': None,
        'caveat': 'Pinning alone does not make an untrusted package safe. This scanner does not verify a live registry.'},
    'resource_exhaustion': {
        'title': 'Give repeated work an explicit bound',
        'steps': ['Define a maximum number of iterations and a cancellation condition.', 'Release sockets, files and workers on all exit paths.', 'Enforce time and memory limits in the runner.'],
        'example': 'MAX_ATTEMPTS = 10\nfor attempt in range(MAX_ATTEMPTS):\n    # Perform one bounded unit of work.\n    # Break when the task completes.\n    pass',
        'caveat': 'An iteration bound does not bound the cost of each iteration. Replace the placeholder with reviewed work and an external deadline.'},
    'ssrf_network_exfil': {
        'title': 'Authorize the final network destination',
        'steps': ['Parse the URL and match exact approved schemes, hosts and ports.', 'Reject redirects or revalidate each redirect destination.', 'Block internal and metadata addresses in runtime egress policy, including resolved addresses.'],
        'example': None,
        'caveat': 'A string-prefix check or static URL check does not stop DNS rebinding. Runtime network enforcement is required.'},
    'ai_targeted_instructions': {
        'title': 'Withhold instructions embedded in untrusted content',
        'steps': ['Remove reviewer/agent override instructions from trusted project content.', 'Quarantine suspicious external output rather than forwarding it as instructions.', 'Keep tool content separate from the agent’s controlling instructions.'],
        'example': None,
        'caveat': 'Deleting one detected phrase does not prove the remaining content is safe. Review the whole trust boundary.'},
}


def suggested_fix(category, reason):
    fix = dict(FIXES[category])
    if category == 'destructive_command' and 'SQL text is dynamic' in reason:
        fix.update(title='Pass SQL values as parameters',
                   example='def find_order(cursor, order_id):\n    cursor.execute(\n        "SELECT id, status FROM orders WHERE id = ?",\n        (order_id,),\n    )\n    return cursor.fetchone()',
                   caveat='Illustrative SQLite value binding. Adapt the query and placeholder syntax to your driver; separately allowlist dynamic identifiers.')
    return {**fix, 'automatic': False, 'language': 'python' if fix['example'] else None}


def finding(category, lines, evidence, reason):
    title, remediation = MESSAGES[category]
    return {'category': category, 'severity': 'high', 'lines': sorted(set(lines)),
            'title': title, 'why': reason, 'remediation': remediation,
            'evidence': evidence, 'rule_id': 'CG-' + category.upper(),
            'fix': suggested_fix(category, reason)}


def assemble(findings, language, complete=True):
    categories = sorted({f['category'] for f in findings})
    lines = sorted({line for f in findings for line in f['lines']})
    risk = min(.98, .8 + .04 * (len(categories) - 1)) if findings else 0.0
    reason = ' '.join(f"Line {f['lines'][0]}: {f['why']}" for f in findings[:2])
    if not complete:
        reason = 'Blocked because this input could not be fully checked by the initial analyzer. ' + reason
    return {'verdict': 'block' if findings or not complete else 'allow',
            'risk_score': round(risk, 2), 'categories': categories,
            'code_language': language,
            'reason': reason or 'No blocking findings in the completed baseline checks.',
            'vulnerable_lines': lines, 'findings': findings,
            'analysis_complete': complete,
            'score_trace': {
                'method': 'baseline-category-count-v1',
                'calibrated_probability': False,
                'formula': '0 with no findings; otherwise min(0.98, 0.80 + 0.04 * (distinct_categories - 1))',
                'base': 0.8 if findings else 0.0,
                'category_bonus': round(0.04 * max(0, len(categories) - 1), 2),
                'cap': 0.98, 'final_score': round(risk, 2),
                'distinct_categories': categories,
                'contributors': [{'rule_id': f['rule_id'], 'category': f['category'], 'lines': f['lines']} for f in findings],
                'decision_basis': 'incomplete_analysis' if not complete else ('findings_present' if findings else 'no_findings'),
                'policy': 'Block on any baseline finding or incomplete analysis. Score does not independently authorize execution.',
                'limitations': 'Hand-set heuristic weights; not trained, calibrated or validated as an attack probability. Multiple findings in one category do not add category bonuses.'},
            'coverage': 'Initial static baseline; bounded, intraprocedural Python checks. No runtime safety guarantee.'}

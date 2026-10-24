"""Rule catalogue served at /v1/rules.

Every entry is metadata over a rule the analyzer actually implements. Rationale
comes from the analyzer's own reason table, so the catalogue cannot drift into
describing checks that do not exist. References are CWE / ATT&CK / ATLAS.
"""
from feat_1_scan.analyzer import PREFIX, REASONS
from feat_2_results.results import MESSAGES

CWE = {
    'SEC': ['CWE-798', 'CWE-200', 'MITRE ATT&CK T1552'],
    'EXF': ['CWE-200', 'CWE-319', 'MITRE ATT&CK T1048.003'],
    'DES': ['CWE-78', 'CWE-89', 'CWE-22'],
    'PER': ['CWE-269', 'CWE-732', 'MITRE ATT&CK T1547'],
    'OBF': ['CWE-94', 'CWE-502', 'MITRE ATT&CK T1027'],
    'DEP': ['CWE-829', 'CWE-1104', 'MITRE ATT&CK T1195'],
    'RES': ['CWE-770', 'CWE-400', 'CWE-835'],
    'NET': ['CWE-918', 'CWE-441'],
    'AIT': ['MITRE ATLAS AML.T0054', 'OWASP LLM01'],
    'CRY': ['CWE-327', 'CWE-295'],
    'WEB': ['CWE-79'],
    'INJ': ['CWE-611', 'CWE-1336'],
}

CRITICAL = frozenset((
    'SEC-002', 'SEC-007', 'EXF-001', 'DES-001', 'DES-002', 'DES-006',
    'PER-001', 'PER-003', 'PER-004', 'PER-007', 'PER-009', 'OBF-001',
    'DEP-007', 'RES-002', 'RES-003', 'NET-001', 'AIT-002', 'AIT-004',
))

MEDIUM = frozenset((
    'SEC-005', 'SEC-009', 'EXF-006', 'EXF-009', 'PER-010', 'OBF-005',
    'OBF-011', 'DEP-004', 'DEP-005', 'DEP-008', 'RES-007', 'RES-009',
    'RES-010', 'RES-011', 'RES-012', 'NET-008', 'NET-009', 'AIT-006',
    'AIT-009', 'CRY-001', 'CRY-002',
))


def _severity(rule):
    if rule in CRITICAL:
        return 'critical'
    if rule in MEDIUM:
        return 'medium'
    return 'high'


def catalogue():
    rules = []
    for rule, rationale in sorted(REASONS.items()):
        prefix = rule.split('-')[0]
        category = PREFIX[prefix]
        title, remediation = MESSAGES[category]
        rules.append({
            'id': 'CG-' + rule,
            'rule_id': rule,
            'category': category,
            'severity': _severity(rule),
            'languages': ['python'] if prefix not in ('AIT',) else
                         ['python', 'bash', 'javascript', 'sql', 'yaml', 'markdown'],
            'matcher': 'AST/taint' if prefix in ('SEC', 'EXF', 'DES', 'PER', 'OBF', 'RES', 'NET')
                       else 'lexical/structure',
            'rationale': rationale,
            'references': CWE.get(prefix, []),
            'remediation': remediation,
            'fixture': 'see backend/feat_6_runtime/test_rules.py',
        })
    return rules

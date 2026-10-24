"""Versioned severity scoring. These numbers are policy weights, not probabilities."""
from math import isfinite, prod

METHOD = 'severity-noisy-or-v1'
BLOCK_THRESHOLD = 0.5
WEIGHTS = {'critical': 1.0, 'high': .8, 'medium': .5, 'low': .25, 'info': .05}
CRITICAL = frozenset(('SEC-002', 'SEC-007', 'EXF-001', 'DES-001', 'DES-002',
    'DES-006', 'PER-001', 'PER-003', 'PER-004', 'PER-007', 'PER-009',
    'OBF-001', 'DEP-007', 'RES-002', 'RES-003', 'NET-001', 'AIT-002', 'AIT-004'))
MEDIUM = frozenset(('SEC-005', 'SEC-009', 'EXF-006', 'EXF-009', 'PER-010',
    'OBF-005', 'OBF-011', 'DEP-004', 'DEP-005', 'RES-007', 'RES-009',
    'RES-010', 'RES-011', 'RES-012', 'NET-008', 'NET-009', 'AIT-006',
    'AIT-009', 'CRY-001', 'CRY-002'))


def severity(rule):
    rule = rule.removeprefix('CG-')
    return ('info' if rule == 'DEP-008' else 'critical' if rule in CRITICAL
            else 'medium' if rule in MEDIUM else 'high')


def aggregate(findings, complete=True):
    contributors, seen = [], set()
    for finding in findings:
        key = (finding['rule_id'], tuple(sorted(set(finding['lines']))))
        if key in seen:
            continue
        seen.add(key)
        confidence = finding.get('confidence', .95)
        if (type(confidence) not in (int, float) or not isfinite(confidence)
                or not 0 <= confidence <= 1):
            raise ValueError('Invalid finding confidence')
        level = finding['severity']
        weight = WEIGHTS[level]
        contributors.append({'rule_id': finding['rule_id'], 'category': finding['category'],
            'lines': finding['lines'], 'severity': level, 'confidence': confidence,
            'severity_weight': weight, 'contribution': weight * confidence})
    category_scores = {category: 1 - prod(1 - f['contribution'] for f in contributors
                       if f['category'] == category)
                       for category in sorted({f['category'] for f in contributors})}
    base = max(category_scores.values(), default=0.0)
    # Each rule below already proves its chain, unlike mere category co-occurrence.
    bonuses = [{'rule_id': rule, 'amount': .03, 'why': why} for rule, why in (
        ('CG-EXF-001', 'The source-to-network rule established sensitive data flow.'),
        ('CG-OBF-001', 'The rule established a decode-to-execution boundary.'))
        if any(f['rule_id'] == rule for f in contributors)]
    bonus = sum(item['amount'] for item in bonuses)
    critical = any(f['severity'] == 'critical' and f['confidence'] >= .9 for f in contributors)
    floor = .9 if critical else 0.0
    raw_score = min(1.0, max(floor, base + bonus))
    # The published two-decimal score is the value compared to the threshold.
    score = round(raw_score, 2)
    basis = ('incomplete_analysis' if not complete else 'critical_rule' if critical
             else 'score_threshold' if score >= BLOCK_THRESHOLD else 'below_threshold')
    verdict = 'block' if not complete or critical or score >= BLOCK_THRESHOLD else 'allow'
    return verdict, score, {
        'method': METHOD, 'calibrated_probability': False,
        'formula': 'finding = severity_weight * confidence; category = 1 - product(1 - finding); score = round(clamp(max(critical_floor, max(category) + chain_bonus + ml_adjustment), 0, 1), 2)',
        'severity_weights': WEIGHTS, 'contributors': contributors,
        'category_scores': category_scores, 'base': base, 'chain_bonuses': bonuses,
        'chain_bonus': bonus, 'critical_floor': floor, 'ml_adjustment': 0.0,
        'ml_status': 'disabled; no trained model adopted', 'unrounded_score': raw_score,
        'final_score': score, 'threshold': BLOCK_THRESHOLD, 'decision_basis': basis,
        'critical_override': critical, 'analysis_complete': complete,
        'policy': 'Block on incomplete analysis, a critical finding with confidence >= 0.9, or published score >= threshold.',
        'confidence_basis': 'Fixed rule-match confidence (0.95 by default), not measured accuracy or a learned probability.',
        'threshold_status': 'PRD default 0.50; development sweep reported separately; no sealed-set calibration.',
        'limitations': 'Correlated findings can inflate noisy-OR. Identical rule/line findings are deduplicated; separate lines can still correlate. Weights, floors and bonuses are engineering policy choices.'}

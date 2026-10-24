"""Lazy decision cards built only for detailed HTTP responses."""
from feat_2_results.scoring import aggregate


def decision_detail(result):
    trace = result.get('score_trace')
    if trace is None:
        _, _, trace = aggregate([], complete=False)
    cards = []
    for finding in result.get('findings', []):
        cards.append({
            'decision': 'Finding contributes to the risk assessment',
            'why': finding['why'],
            'evidence': {'lines': finding['lines'], 'redacted_snippet': finding['evidence']},
            'rule_id': finding['rule_id'], 'confidence': finding.get('confidence', .95),
            'confidence_basis': trace['confidence_basis'], 'severity': finding['severity'],
            'alternatives_considered': finding.get('alternatives_considered', []),
            'alternative_status': 'Review guidance; these alternatives are not a record of evaluated branches.',
            'guards_checked': finding.get('guards_checked', []),
            'guard_evidence_status': finding.get('guard_evidence_status'),
            'references': finding.get('references', []), 'remediation': finding['remediation']})
    cards.append({
        'decision': result['verdict'], 'why': result['reason'],
        'evidence': {'lines': result['vulnerable_lines'], 'redacted_snippet': 'See the structured findings.'},
        'rule_id': 'POLICY', 'confidence': None, 'severity': None,
        'alternatives_considered': ['Allow only if analysis completed and no blocking policy condition holds.'],
        'guards_checked': [
            {'guard': 'analysis_complete', 'result': result.get('analysis_complete') is True},
            {'guard': 'score_below_threshold', 'result': result['risk_score'] < trace['threshold']},
            {'guard': 'no_critical_override', 'result': not trace['critical_override']}],
        'references': ['prd.md §7.7'],
        'remediation': 'Review findings and rescan changed source; an allow verdict is not a runtime safety guarantee.',
        'decision_basis': trace['decision_basis']})
    return {'score_trace': trace, 'decision_cards': cards}

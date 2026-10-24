"""Small fixed-schema boundary shared by normal and degraded responses."""
FIELDS = ('verdict', 'risk_score', 'categories', 'code_language', 'reason', 'vulnerable_lines')
CATEGORIES = frozenset(('secret_access', 'data_exfiltration', 'destructive_command',
    'persistence_or_privesc', 'obfuscated_execution', 'dependency_risk',
    'resource_exhaustion', 'ssrf_network_exfil', 'ai_targeted_instructions'))
LANGUAGES = frozenset(('python', 'bash', 'sql', 'javascript', 'yaml', 'markdown', 'unknown'))


def blocked(reason):
    return dict(verdict='block', risk_score=0.0, categories=[], code_language='unknown',
                reason=reason, vulnerable_lines=[], degraded=True, analysis_complete=False,
                findings=[], decision_basis='incomplete_analysis')


def valid(result, line_count):
    import math
    try:
        return (result['verdict'] in ('allow', 'block')
            and type(result['risk_score']) in (int, float)
            and math.isfinite(result['risk_score']) and 0 <= result['risk_score'] <= 1
            and isinstance(result['categories'], list)
            and all(isinstance(c, str) and c in CATEGORIES for c in result['categories'])
            and len(set(result['categories'])) == len(result['categories'])
            and result['code_language'] in LANGUAGES
            and isinstance(result['reason'], str) and bool(result['reason'])
            and isinstance(result['vulnerable_lines'], list)
            and all(type(n) is int and 1 <= n <= line_count for n in result['vulnerable_lines'])
            and result['vulnerable_lines'] == sorted(set(result['vulnerable_lines'])))
    except (KeyError, TypeError):
        return False

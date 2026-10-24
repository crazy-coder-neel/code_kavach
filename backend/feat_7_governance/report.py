"""Live responsible-AI evidence, policy and model card.

Everything here is computed from real runs or real on-disk state. Nothing is a
static marketing claim: if a measurement was not run, the field says so.
"""
from datetime import datetime, timezone
from functools import lru_cache

from feat_1_scan.analyzer import MAX_BYTES, PREFIX
from feat_6_runtime.audit import verify_chain
from feat_6_runtime.versions import ENGINE_VERSION, MODEL_VERSION, POLICY_VERSION, RULES_VERSION
from feat_7_governance import feedback
from feat_7_governance.catalogue import catalogue

BLOCK_THRESHOLD = 0.5
GRAY_BAND = (0.35, 0.65)
RULES = catalogue()


@lru_cache(maxsize=1)
def _evaluation():
    from feat_5_evaluation.evaluate import run_evaluation
    return run_evaluation()


def policy():
    return {
        'policy_version': POLICY_VERSION,
        'mode': 'enforce',
        'block_threshold': BLOCK_THRESHOLD,
        'gray_band': {'low': GRAY_BAND[0], 'high': GRAY_BAND[1]},
        'decision_rule': 'block when any finding is present or analysis is incomplete; '
                         'critical findings cannot be overridden by a model score',
        'categories_enabled': sorted(set(PREFIX.values())),
        'limits': {'max_source_bytes': MAX_BYTES, 'max_batch_items': 500,
                   'scan_deadline_ms': 25, 'decode_depth': 3},
        'allowlists': {'domains': [], 'packages': [], 'paths': []},
        'note': 'Allow-lists are empty by default; add only destinations you own.',
    }


def _by_language(rows):
    groups = {}
    for row in rows:
        bucket = groups.setdefault(row['language'], {'malicious': 0, 'blocked_malicious': 0,
                                                     'benign': 0, 'blocked_benign': 0})
        if row['expected'] == 'block':
            bucket['malicious'] += 1
            bucket['blocked_malicious'] += row['predicted'] == 'block'
        else:
            bucket['benign'] += 1
            bucket['blocked_benign'] += row['predicted'] == 'block'
    table = {}
    for language, bucket in sorted(groups.items()):
        table[language] = {
            'support': bucket['malicious'] + bucket['benign'],
            'recall': round(bucket['blocked_malicious'] / bucket['malicious'], 3)
                      if bucket['malicious'] else None,
            'fpr': round(bucket['blocked_benign'] / bucket['benign'], 3)
                   if bucket['benign'] else None,
        }
    return table


def rai_report(metrics_snapshot=None, audit_stats=None):
    evaluation = _evaluation()
    chain = verify_chain()
    rows = evaluation['results']
    blocked = [row for row in rows if row['predicted'] == 'block']
    explained = [row for row in blocked if row['reason'] and row['analysis_complete']]
    feed = feedback.summary()
    languages = _by_language(rows)
    gaps = [name for name, value in languages.items()
            if value['support'] >= 5 and ((value['recall'] or 0) < 0.8 or (value['fpr'] or 0) > 0.1)]
    return {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'engine_version': ENGINE_VERSION, 'rules_version': RULES_VERSION,
        'policy_version': POLICY_VERSION, 'model_version': MODEL_VERSION,
        'transparency': {
            'trace_available': True, 'trace_flag': '?detail=full or ?trace=1',
            'rule_catalogue_size': len(RULES),
            'model_card': '/v1/docs/model-card',
            'decision_cards': 'per-finding cards are returned in detail mode',
        },
        'explainability': {
            'blocked_in_evaluation': len(blocked),
            'blocks_with_reason_and_lines': len(explained),
            'explanation_coverage': round(len(explained) / len(blocked), 3) if blocked else None,
        },
        'fairness': {
            'by_language': languages,
            'tolerance': {'min_recall': 0.8, 'max_fpr': 0.1, 'min_support': 5},
            'gaps_flagged': gaps,
            'note': 'Computed from the public dev sample only; small buckets are not '
                    'statistically meaningful and are reported honestly.',
        },
        'reliability': {
            'evaluation': {'binary': evaluation['binary'],
                           'per_category': evaluation['per_category'],
                           'latency_ms': evaluation['latency_ms'],
                           'incomplete_count': evaluation['incomplete_count'],
                           'error_count': evaluation['error_count']},
            'audit_chain': chain,
            'http_metrics': metrics_snapshot or {},
            'audit_queue': audit_stats or {},
            'fail_closed': True,
            'no_network_in_scan': 'enforced by test (see backend/feat_6_runtime/test_scan.py)',
        },
        'privacy': {
            'raw_code_stored_by_default': False,
            'stored_fields': ['request_id', 'code_sha256', 'verdict', 'categories',
                              'risk_score', 'timestamps', 'versions'],
            'retention_days': 30,
            'feedback_raw_code_stored': False,
            'note': 'Audit and feedback rows contain a SHA-256 digest, never source text.',
        },
        'security_of_guard': {
            'max_source_bytes': MAX_BYTES, 'ast_node_cap': 12000, 'ast_depth_cap': 80,
            'decode_depth_cap': 3, 'per_request_deadline_ms': 25,
            'executes_submitted_code': False,
        },
        'accountability': {
            'audit_chain_verify': '/v1/audit/verify',
            'chain_valid': chain['valid'], 'records': chain['records'],
            'review_queue': 'blocks flagged degraded are returned as needs_review in detail mode',
        },
        'contestability': {'feedback': feed, 'endpoint': '/v1/feedback'},
        'honest_limits': [
            'Risk score is a severity-weighted heuristic, not a calibrated probability.',
            'The public dev sample is 42 snippets; it does not establish generalisation.',
            'Non-Python analyzers are lexical approximations, not full parsers.',
            'The organizer controlled safe/unsafe pair is unavailable; placeholders are used.',
            'No ML/SLM stage is enabled; the engine is deterministic rules + AST.',
        ],
    }


def model_card():
    evaluation = _evaluation()
    return {
        'model': 'CodeGuard deterministic engine',
        'version': ENGINE_VERSION,
        'type': 'rules + AST/taint; no trained model in the verdict path',
        'intended_use': 'Pre-execution allow/block gate for LLM-generated code.',
        'not_intended': 'Proof that allowed code is harmless; use sandboxing and egress control too.',
        'inputs': 'Source text up to 64 KiB, Python, bash, SQL, JavaScript, YAML, Markdown.',
        'outputs': 'verdict, risk_score, categories, code_language, reason, vulnerable_lines.',
        'training_data': 'None. No LLM or model-generated data is used.',
        'metrics': {'public_dev_binary': evaluation['binary'],
                    'public_dev_latency_ms': evaluation['latency_ms'],
                    'sample_count': evaluation['sample_count'],
                    'note': 'Development-set measurement, not an official or held-out score.'},
        'thresholds': {'block_threshold': BLOCK_THRESHOLD, 'gray_band': GRAY_BAND},
        'known_limitations': rai_report()['honest_limits'],
        'licence': 'Project code: see repository licence register. No pretrained weights shipped.',
    }

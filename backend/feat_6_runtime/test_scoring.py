import math
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from main import app
from feat_1_scan.analyzer import analyze
from feat_2_results.scoring import aggregate
from feat_6_runtime.contract import FIELDS, CATEGORIES
from feat_6_runtime.test_rules import FIXTURES


def item(rule='CG-TEST', category='secret_access', severity='high', confidence=.95, lines=None):
    return dict(rule_id=rule, category=category, severity=severity,
                confidence=confidence, lines=lines or [1])


class ScoringTests(unittest.TestCase):
    def test_arithmetic_and_deduplication(self):
        one = item()
        verdict, score, trace = aggregate([one, one, item(rule='CG-OTHER')])
        self.assertEqual(verdict, 'block')
        self.assertAlmostEqual(trace['category_scores']['secret_access'], 1 - .24**2)
        self.assertEqual(score, .94)
        self.assertEqual(len(trace['contributors']), 2)

    def test_medium_info_and_fail_closed(self):
        self.assertEqual(aggregate([item(severity='medium')])[:2], ('allow', .47))
        self.assertEqual(aggregate([item(severity='info')])[0], 'allow')
        self.assertEqual(aggregate([], complete=False)[:2], ('block', 0.0))

    def test_critical_floor_and_chain_bonus(self):
        verdict, score, trace = aggregate([item(rule='CG-EXF-001', severity='critical')])
        self.assertEqual((verdict, score), ('block', .98))
        self.assertEqual(trace['critical_floor'], .9)
        self.assertEqual(trace['chain_bonus'], .03)
        self.assertTrue(trace['critical_override'])

    def test_invalid_confidence_never_scores(self):
        for value in (float('nan'), float('inf'), -1, 2, True):
            with self.assertRaises(ValueError):
                aggregate([item(confidence=value)])

    def test_all_nine_categories_have_live_findings(self):
        observed = set()
        for positive, _ in FIXTURES.values():
            result = analyze(positive)
            observed.update(result['categories'])
            trace = result['score_trace']
            self.assertEqual(trace['final_score'], result['risk_score'])
            self.assertTrue(math.isfinite(result['risk_score']))
            for finding in result['findings']:
                self.assertTrue(finding['why'])
                self.assertTrue(finding['lines'])
                self.assertTrue(finding['remediation'])
        self.assertEqual(observed, CATEGORIES)

    def test_detail_and_trace_opt_in_with_operational_failure(self):
        client = TestClient(app)
        with patch('main.decision_detail', wraps=__import__('main').decision_detail) as builder:
            strict = client.post('/v1/guard', json={'code': 'value=1'}).json()
            self.assertEqual(set(strict), set(FIELDS))
            builder.assert_not_called()
        for query in ('?detail=full', '?trace=1'):
            for code in ('value=1', 'exec(payload)', ''):
                result = client.post('/v1/guard' + query, json={'code': code}).json()
                self.assertEqual(result['decision_cards'][-1]['decision'], result['verdict'])
                self.assertEqual(result['score_trace']['final_score'], result['risk_score'])

    def test_sensitive_values_absent_from_detail(self):
        token = 'AKIAABCDEFGHIJKLMNOP'
        result = TestClient(app).post('/v1/guard?detail=full', json={'code': f'key="{token}"'})
        self.assertNotIn(token, result.text)

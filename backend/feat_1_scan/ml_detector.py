"""CPU-first Classical ML Detector for CodeGuard.

A lightweight, local, multi-label classifier built with scikit-learn.
Infers in < 1 ms on CPU, requiring 0 GPU memory and 0 external network/LLM calls.
"""
import ast
import math
import os
from pathlib import Path
import re
from time import perf_counter
from typing import Any, Dict, List, Optional

try:
    import joblib
    import numpy as np
    _SKLEARN_AVAILABLE = True
except ImportError:
    joblib = None
    np = None
    _SKLEARN_AVAILABLE = False

CATEGORIES = [
    'secret_access',
    'data_exfiltration',
    'destructive_command',
    'persistence_or_privesc',
    'obfuscated_execution',
    'dependency_risk',
    'resource_exhaustion',
    'ssrf_network_exfil',
    'ai_targeted_instructions',
]

MODEL_PATH = Path(__file__).parent / 'models' / 'classifier.joblib'
M2_MODEL_PATH = Path(__file__).parent / 'models' / 'm2_injection.joblib'

KEYWORD_PATTERNS = [
    ('subproc', re.compile(r'\b(subprocess|os\.system|popen|spawn)\b', re.I)),
    ('eval_exec', re.compile(r'\b(eval|exec|compile|__import__|getattr)\b', re.I)),
    ('file_delete', re.compile(r'rm\s+-rf|shutil\.rmtree|os\.remove|unlink', re.I)),
    ('sql_injection', re.compile(r'DROP\s+TABLE|UNION\s+SELECT|SELECT\s+\*\s+FROM|\bWHERE\b.*%s', re.I)),
    ('cloud_metadata', re.compile(r'169\.254\.169\.254|metadata\.google\.internal', re.I)),
    ('internal_net', re.compile(r'127\.0\.0\.1|localhost|10\.\d+|192\.168\.', re.I)),
    ('obfuscation_b64', re.compile(r'b64decode|base64|fromkeys', re.I)),
    ('persistence', re.compile(r'crontab|systemd|init\.d|bashrc|profile|authorized_keys', re.I)),
    ('privilege', re.compile(r'sudo|chmod\s+777|setuid|chown', re.I)),
    ('env_secrets', re.compile(r'environ\.get|os\.environ|AWS_SECRET|API_KEY|PASSWORD|TOKEN', re.I)),
    ('ai_instruction', re.compile(r'ignore\s+(?:previous|all)\s+instructions|system\s+prompt|mark\s+as\s+safe', re.I)),
    ('infinite_loop', re.compile(r'while\s+(?:True|1)\b', re.I)),
    ('unpinned_pkg', re.compile(r'pip\s+install|npm\s+install|extra-index-url|--trusted-host', re.I)),
]


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


def extract_structural_features(code: str, findings: Optional[List[Dict[str, Any]]] = None) -> List[float]:
    features = []
    # 1. Size & line metrics
    features.append(len(code) / 1000.0)
    features.append(code.count('\n') / 100.0)

    # 2. String entropy
    string_literals = re.findall(r'["\']([^"\']{8,})["\']', code)
    max_ent = max((shannon_entropy(s) for s in string_literals), default=0.0)
    features.append(max_ent / 8.0)

    # 3. Domain regex patterns
    for _, pat in KEYWORD_PATTERNS:
        features.append(1.0 if pat.search(code) else 0.0)

    # 4. AST node analysis (if Python)
    try:
        tree = ast.parse(code)
        calls = sum(1 for _ in ast.walk(tree) if isinstance(_, ast.Call))
        imports = sum(1 for _ in ast.walk(tree) if isinstance(_, (ast.Import, ast.ImportFrom)))
        loops = sum(1 for _ in ast.walk(tree) if isinstance(_, (ast.While, ast.For)))
        attributes = sum(1 for _ in ast.walk(tree) if isinstance(_, ast.Attribute))
        features.extend([calls / 10.0, imports / 5.0, loops / 5.0, attributes / 10.0, 0.0])
    except Exception:
        # Non-Python or unparseable
        features.extend([0.0, 0.0, 0.0, 0.0, 1.0])

    # 5. Rule vector if findings provided
    if findings:
        cat_set = set(f.get('category') for f in findings)
        cats_vec = [1.0 if c in cat_set else 0.0 for c in CATEGORIES]
        features.extend(cats_vec)
        features.append(float(len(findings)) / 5.0)
    else:
        features.extend([0.0] * (len(CATEGORIES) + 1))

    return features


class MLDetector:
    _instance = None

    def __init__(self, model_file: Optional[Path] = None):
        self.model_path = model_file or MODEL_PATH
        self.m2_path = M2_MODEL_PATH
        self.bundle = None
        self.m2_bundle = None
        self._load()

    def _load(self):
        if not _SKLEARN_AVAILABLE:
            return
        if self.model_path.exists():
            try:
                self.bundle = joblib.load(self.model_path)
            except Exception:
                self.bundle = None
        if self.m2_path.exists():
            try:
                self.m2_bundle = joblib.load(self.m2_path)
            except Exception:
                self.m2_bundle = None

    def predict_injection(self, text: str) -> Dict[str, Any]:
        """M2 CG-Inj text classifier for prompt-injection detection on extracted text."""
        if not self.m2_bundle or not isinstance(text, str) or not text.strip():
            return {'available': False, 'is_injection': False, 'confidence': 0.0, 'signals': []}
        clean = text.strip()
        # Prompt injection in code requires meaningful prose length
        if len(clean.split()) < 3 or len(clean) < 15:
            return {'available': True, 'is_injection': False, 'confidence': 0.0, 'signals': []}
        try:
            vec = self.m2_bundle['vectorizer']
            clf = self.m2_bundle['classifier']
            X = vec.transform([clean])
            prob = float(clf.predict_proba(X)[0][1])
            is_inj = prob >= 0.75
            return {
                'available': True,
                'is_injection': is_inj,
                'confidence': round(prob, 4),
                'signals': ['m2_injection_classifier'] if is_inj else []
            }
        except Exception:
            return {'available': False, 'is_injection': False, 'confidence': 0.0, 'signals': []}

    @property
    def is_available(self) -> bool:
        return self.bundle is not None

    def predict(self, code: str, findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        if not self.is_available:
            return {
                'available': False,
                'malicious_prob': 0.0,
                'category_probs': {},
                'predicted_categories': [],
                'top_signals': [],
                'latency_ms': 0.0,
            }

        start = perf_counter()
        try:
            vec = self.bundle['vectorizer']
            clf_binary = self.bundle['binary_clf']
            clf_multi = self.bundle['multi_clf']

            # Vectorize code text
            text_feat = vec.transform([code]).toarray()
            # Extract structural + rule features
            struct_feat = np.array([extract_structural_features(code, findings)])
            X_combined = np.hstack([text_feat, struct_feat])

            # Binary probability of maliciousness
            if hasattr(clf_binary, 'predict_proba'):
                prob_arr = clf_binary.predict_proba(X_combined)[0]
                malicious_prob = float(prob_arr[1]) if len(prob_arr) > 1 else float(prob_arr[0])
            else:
                malicious_prob = float(clf_binary.predict(X_combined)[0])

            # Multi-label category probabilities
            category_probs = {}
            if hasattr(clf_multi, 'predict_proba'):
                multi_probs = clf_multi.predict_proba(X_combined)[0]
                for cat, p in zip(CATEGORIES, multi_probs):
                    category_probs[cat] = round(float(p), 4)
            else:
                preds = clf_multi.predict(X_combined)[0]
                for cat, p in zip(CATEGORIES, preds):
                    category_probs[cat] = float(p)

            predicted_categories = [cat for cat, p in category_probs.items() if p >= 0.50]

            # Top keyword signals
            top_signals = [name for name, pat in KEYWORD_PATTERNS if pat.search(code)]

            duration_ms = round((perf_counter() - start) * 1000, 3)
            return {
                'available': True,
                'malicious_prob': round(malicious_prob, 4),
                'category_probs': category_probs,
                'predicted_categories': predicted_categories,
                'top_signals': top_signals,
                'latency_ms': duration_ms,
            }
        except Exception:
            return {
                'available': False,
                'malicious_prob': 0.0,
                'category_probs': {},
                'predicted_categories': [],
                'top_signals': [],
                'latency_ms': round((perf_counter() - start) * 1000, 3),
            }


_detector_instance: Optional[MLDetector] = None


def get_detector() -> MLDetector:
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = MLDetector()
        if _detector_instance.is_available:
            _detector_instance.predict('warmup=1', [])
    return _detector_instance


try:
    get_detector()
except Exception:
    pass


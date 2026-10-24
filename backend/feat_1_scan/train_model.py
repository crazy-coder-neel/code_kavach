"""Offline deterministic training script for CodeGuard CPU ML Classifier.

Trains a compact, multi-label classifier on CPU using scikit-learn.
Saves the artifact to backend/feat_1_scan/models/classifier.joblib.
Zero external LLM API calls.
"""
import json
import os
from pathlib import Path
import sys
import time

# Ensure backend is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report

from feat_1_scan.analyzer import analyze
from feat_1_scan.ml_detector import (
    CATEGORIES,
    extract_structural_features,
    MODEL_PATH,
)
from feat_6_runtime.test_rules import FIXTURES, SUPPLEMENTAL_FIXTURES
from feat_6_runtime.test_benign import BENIGN

PREFIX = dict(
    SEC='secret_access', EXF='data_exfiltration', DES='destructive_command',
    PER='persistence_or_privesc', OBF='obfuscated_execution', DEP='dependency_risk',
    RES='resource_exhaustion', NET='ssrf_network_exfil', AIT='ai_targeted_instructions',
    CRY='secret_access', WEB='obfuscated_execution', INJ='destructive_command'
)


def load_dataset():
    dataset = []

    # 1. codeguard_dev.jsonl
    dev_path = BASE_DIR.parent / 'codeguard_dev.jsonl'
    if dev_path.exists():
        with open(dev_path, 'r', encoding='utf-8') as f:
            for line in f:
                item = json.loads(line)
                cats = [c.strip() for c in item['category'].split(',')] if item['category'] != 'benign' else []
                dataset.append({
                    'code': item['code'],
                    'categories': cats,
                    'is_malicious': item['label'] == 1,
                    'source': 'dev'
                })

    # 2. FIXTURES
    for rule, (pos, neg) in FIXTURES.items():
        cat = PREFIX.get(rule.split('-')[0], 'obfuscated_execution')
        dataset.append({'code': pos, 'categories': [cat], 'is_malicious': True, 'source': f'fixture_{rule}'})
        dataset.append({'code': neg, 'categories': [], 'is_malicious': False, 'source': f'benign_{rule}'})

    # 3. SUPPLEMENTAL_FIXTURES
    for rule, (pos, neg) in SUPPLEMENTAL_FIXTURES.items():
        cat = PREFIX.get(rule.split('-')[0], 'obfuscated_execution')
        dataset.append({'code': pos, 'categories': [cat], 'is_malicious': True, 'source': f'supp_{rule}'})
        dataset.append({'code': neg, 'categories': [], 'is_malicious': False, 'source': f'supp_benign_{rule}'})

    # 4. BENIGN
    for k, code in BENIGN.items():
        dataset.append({'code': code, 'categories': [], 'is_malicious': False, 'source': f'benign_{k}'})

    # 5. Deterministic synthetic templates (offline, zero LLM)
    try:
        from feat_3_ml.generators import generate_dataset
        syn_samples = generate_dataset(samples_per_category=5, benign_samples=15)
        for s in syn_samples:
            cats = [s['category']] if s['category'] != 'benign' else []
            dataset.append({
                'code': s['code'],
                'categories': cats,
                'is_malicious': s['label'] == 1,
                'source': f"syn_{s['template_id']}"
            })
    except ImportError:
        pass

    return dataset


def train():
    print('Loading dataset...')
    data = load_dataset()
    print(f'Total samples: {len(data)}')
    mal_count = sum(1 for d in data if d['is_malicious'])
    ben_count = sum(1 for d in data if not d['is_malicious'])
    print(f'Malicious: {mal_count}, Benign: {ben_count}')

    X_raw = [d['code'] for d in data]
    y_binary = np.array([1 if d['is_malicious'] else 0 for d in data])

    y_multilabel = np.zeros((len(data), len(CATEGORIES)), dtype=int)
    for i, d in enumerate(data):
        for cat in d['categories']:
            if cat in CATEGORIES:
                y_multilabel[i, CATEGORIES.index(cat)] = 1

    print('Extracting static features for training samples...')
    struct_features = []
    for code in X_raw:
        res = analyze(code)
        findings = res.get('findings', [])
        struct_features.append(extract_structural_features(code, findings))
    struct_mat = np.array(struct_features)

    print('Fitting TF-IDF vectorizer...')
    vec = TfidfVectorizer(
        ngram_range=(1, 3),
        analyzer='char_wb',
        max_features=1200,
        sublinear_tf=True
    )
    tfidf_mat = vec.fit_transform(X_raw).toarray()
    X_combined = np.hstack([tfidf_mat, struct_mat])
    print(f'Feature matrix shape: {X_combined.shape}')

    # 5-fold CV evaluation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    binary_clf = LogisticRegression(C=2.0, max_iter=1000, class_weight='balanced')
    f1_scores = cross_val_score(binary_clf, X_combined, y_binary, cv=cv, scoring='f1')
    acc_scores = cross_val_score(binary_clf, X_combined, y_binary, cv=cv, scoring='accuracy')
    print(f'Binary Classifier 5-Fold CV F1: {f1_scores.mean():.4f} (+/- {f1_scores.std():.4f})')
    print(f'Binary Classifier 5-Fold CV Accuracy: {acc_scores.mean():.4f}')

    # Train final binary classifier
    binary_clf.fit(X_combined, y_binary)

    # Train multi-label classifier
    multi_clf = OneVsRestClassifier(LogisticRegression(C=2.0, max_iter=1000, class_weight='balanced'))
    multi_clf.fit(X_combined, y_multilabel)

    preds = multi_clf.predict(X_combined)
    print('\nMulti-Label Classification Report:')
    print(classification_report(y_multilabel, preds, target_names=CATEGORIES, zero_division=0))

    # Save bundle
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    bundle = {
        'vectorizer': vec,
        'binary_clf': binary_clf,
        'multi_clf': multi_clf,
        'categories': CATEGORIES,
        'created_at': time.time(),
        'feature_dim': X_combined.shape[1],
    }
    joblib.dump(bundle, MODEL_PATH, compress=3)
    file_size_kb = os.path.getsize(MODEL_PATH) / 1024
    print(f'Model bundle successfully saved to {MODEL_PATH} ({file_size_kb:.1f} KB)')


if __name__ == '__main__':
    train()

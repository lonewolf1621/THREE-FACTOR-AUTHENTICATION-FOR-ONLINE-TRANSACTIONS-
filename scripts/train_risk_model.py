"""Train the login and payment risk models on simulated behaviour.

There is no public dataset of labelled account-takeover attempts with these
signals, so this script simulates them: genuine users mostly sign in from
known devices and networks at their usual hours and pay known payees typical
amounts; account-takeover attempts mostly come from new devices and
networks, at odd hours, after failed attempts, and send larger amounts to
new payees. Overlap is deliberate (travel, new phones, first-time payees,
careful attackers), so the task is not trivial.

Writes app/risk_model.json (coefficients only) and docs/risk_model_metrics.json.

    python scripts/train_risk_model.py
"""
import json
import os
import sys

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import train_test_split

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
LOGIN = ["new_device", "new_network", "odd_hour", "recent_failures"]
PAYMENT = LOGIN + ["amount_ratio", "new_payee", "velocity"]

rng = np.random.default_rng(42)
N, FRAUD_RATE = 60_000, 0.03


def simulate(n, fraud):
    if not fraud:
        d = {
            "new_device": rng.random(n) < 0.08,
            "new_network": rng.random(n) < 0.18,
            "odd_hour": rng.beta(1.3, 6, n),
            "recent_failures": np.minimum(rng.poisson(0.15, n), 5) / 5,
            "amount_ratio": np.clip(rng.normal(0.0, 0.35, n), -1, 3),
            "new_payee": rng.random(n) < 0.2,
            "velocity": np.minimum(rng.poisson(0.2, n), 5) / 5,
        }
    else:
        d = {
            "new_device": rng.random(n) < 0.7,
            "new_network": rng.random(n) < 0.75,
            "odd_hour": rng.beta(2.0, 2.5, n),
            "recent_failures": np.minimum(rng.poisson(1.2, n), 5) / 5,
            "amount_ratio": np.clip(rng.normal(0.8, 0.6, n), -1, 3),
            "new_payee": rng.random(n) < 0.8,
            "velocity": np.minimum(rng.poisson(1.0, n), 5) / 5,
        }
    return {k: v.astype(float) for k, v in d.items()}


def build():
    n_f = int(N * FRAUD_RATE)
    good, bad = simulate(N - n_f, False), simulate(n_f, True)
    X = {k: np.concatenate([good[k], bad[k]]) for k in PAYMENT}
    y = np.concatenate([np.zeros(N - n_f), np.ones(n_f)])
    return X, y


def fit(X, y, feats):
    A = np.column_stack([X[f] for f in feats])
    A_tr, A_te, y_tr, y_te = train_test_split(A, y, test_size=0.25, stratify=y, random_state=0)
    clf = LogisticRegression(max_iter=1000, C=1.0).fit(A_tr, y_tr)
    p = clf.predict_proba(A_te)[:, 1]
    metrics = {"roc_auc": round(float(roc_auc_score(y_te, p)), 4),
               "pr_auc": round(float(average_precision_score(y_te, p)), 4),
               "test_size": int(len(y_te)), "fraud_rate": FRAUD_RATE}
    for t in (0.25, 0.6, 0.9):
        flagged = p >= t
        metrics[f"at_{t}"] = {
            "flagged_share": round(float(flagged.mean()), 4),
            "fraud_caught": round(float(flagged[y_te == 1].mean()), 4),
            "genuine_challenged": round(float(flagged[y_te == 0].mean()), 4),
        }
    model = {"features": feats, "intercept": round(float(clf.intercept_[0]), 5),
             "weights": {f: round(float(w), 5) for f, w in zip(feats, clf.coef_[0])}}
    return model, metrics


def main():
    X, y = build()
    login_model, login_metrics = fit(X, y, LOGIN)
    payment_model, payment_metrics = fit(X, y, PAYMENT)
    out = {"_note": "Trained on simulated behaviour by scripts/train_risk_model.py; see docs/risk_model.md",
           "login": login_model, "payment": payment_model}
    with open(os.path.join(ROOT, "app", "risk_model.json"), "w") as fh:
        json.dump(out, fh, indent=2)
    with open(os.path.join(ROOT, "docs", "risk_model_metrics.json"), "w") as fh:
        json.dump({"login": login_metrics, "payment": payment_metrics, "samples": N, "seed": 42}, fh, indent=2)
    print(json.dumps({"login": login_metrics, "payment": payment_metrics}, indent=2))


if __name__ == "__main__":
    main()

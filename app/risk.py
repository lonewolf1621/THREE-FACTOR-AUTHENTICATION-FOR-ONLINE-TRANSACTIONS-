"""Risk scoring for logins and payments.

Signals come from the user's own history (devices, networks, usual hours,
payees and amounts). A logistic-regression model, trained by
``scripts/train_risk_model.py`` and stored as plain coefficients in
``risk_model.json``, turns them into a probability that the attempt is an
account takeover. Scoring needs no ML library at runtime, and every score
comes with the signals that drove it.

The model is trained on SIMULATED behaviour (see docs/risk_model.md): it
shows the method, not a production fraud model. A real deployment would
retrain on labelled fraud and chargeback data.
"""
from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass, field
from typing import Dict, List

LOGIN_FEATURES = ["new_device", "new_network", "odd_hour", "recent_failures"]
PAYMENT_FEATURES = LOGIN_FEATURES + ["amount_ratio", "new_payee", "velocity"]

LABELS = {
    "new_device": "new device",
    "new_network": "new network",
    "odd_hour": "unusual time of day",
    "recent_failures": "recent failed attempts",
    "amount_ratio": "amount much higher than usual",
    "new_payee": "new payee",
    "velocity": "several payments in a short time",
}

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "risk_model.json")
with open(_MODEL_PATH) as fh:
    MODEL = json.load(fh)


@dataclass
class Risk:
    score: float
    features: Dict[str, float]
    reasons: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"score": round(self.score, 3), "level": level(self.score), "reasons": self.reasons,
                "signals": {k: round(v, 3) for k, v in self.features.items()}}


def level(score: float) -> str:
    return "high" if score >= 0.6 else "medium" if score >= 0.25 else "low"


def _hour_distance(hour: float, hours: List[float]) -> float:
    """0 = typical hour for this user, 1 = 12 hours away from their usual time."""
    if len(hours) < 3:
        return 0.0
    angles = [h / 24 * 2 * math.pi for h in hours]
    mean = math.atan2(sum(math.sin(a) for a in angles), sum(math.cos(a) for a in angles))
    diff = abs(hour / 24 * 2 * math.pi - mean) % (2 * math.pi)
    diff = min(diff, 2 * math.pi - diff)
    return diff / math.pi


def _median(values: List[float]) -> float:
    s = sorted(values)
    if not s:
        return 0.0
    mid = len(s) // 2
    return s[mid] if len(s) % 2 else (s[mid - 1] + s[mid]) / 2


def login_features(*, device_known: bool, network_known: bool, hour: float,
                   past_hours: List[float], failures_last_hour: int) -> Dict[str, float]:
    return {
        "new_device": 0.0 if device_known else 1.0,
        "new_network": 0.0 if network_known else 1.0,
        "odd_hour": _hour_distance(hour, past_hours),
        "recent_failures": min(failures_last_hour, 5) / 5,
    }


def payment_features(base: Dict[str, float], *, amount: float, past_amounts: List[float],
                     payee_known: bool, payments_last_hour: int) -> Dict[str, float]:
    typical = max(_median(past_amounts), 20.0)
    ratio = math.log10(max(amount, 0.01) / typical)
    return {**base,
            "amount_ratio": max(-1.0, min(3.0, ratio)),
            "new_payee": 0.0 if payee_known else 1.0,
            "velocity": min(payments_last_hour, 5) / 5}


def score(kind: str, features: Dict[str, float]) -> Risk:
    m = MODEL[kind]
    contributions = {f: m["weights"][f] * features[f] for f in m["features"]}
    z = m["intercept"] + sum(contributions.values())
    p = 1 / (1 + math.exp(-z))
    reasons = [LABELS[f] for f, c in sorted(contributions.items(), key=lambda kv: -kv[1])
               if c > 0.4]
    return Risk(score=p, features=features, reasons=reasons)

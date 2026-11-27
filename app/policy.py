"""Which factors an attempt needs, given its risk.

Three factors:
  password  – something you know
  totp      – something you have (authenticator app)
  passkey   – something you are (fingerprint / face via WebAuthn, user verification required)

Payments follow the shape of PSD2 Strong Customer Authentication:
  * low-value exemption: up to 30 (GBP/EUR) with no step-up, while the payments
    made since the last full authentication stay under 100 and 5 in number
    (RTS Article 16), and only when risk is low;
  * otherwise at least two factors, and the passkey for high-value or high-risk payments;
  * the passkey challenge is bound to the amount and payee ("dynamic linking", RTS Article 5).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

LOW_VALUE_LIMIT = 30.0
CUMULATIVE_LIMIT = 100.0
CUMULATIVE_COUNT = 5
HIGH_VALUE = 500.0
MEDIUM_RISK = 0.25
HIGH_RISK = 0.6
BLOCK_RISK = 0.9


@dataclass
class Decision:
    status: str              # "approved" | "step_up" | "blocked"
    required: List[str]      # factors still to verify for this attempt
    reason: str

    def as_dict(self) -> dict:
        return {"status": self.status, "required": self.required, "reason": self.reason}


def login_requirements(risk: float, has_totp: bool, has_passkey: bool) -> List[str]:
    """Password is always checked first; extra factors depend on risk."""
    needed = []
    if has_totp and (risk >= MEDIUM_RISK or not has_passkey):
        needed.append("totp")
    if has_passkey and risk >= HIGH_RISK:
        needed.append("passkey")
    if has_passkey and not has_totp and risk >= MEDIUM_RISK:
        needed.append("passkey")
    # A known, low-risk device still proves possession with one factor
    # when the user has enrolled both.
    if has_totp and has_passkey and not needed:
        needed.append("totp")
    return sorted(set(needed), key=["totp", "passkey"].index)


def payment_decision(amount: float, risk: float, exempt_total: float, exempt_count: int) -> Decision:
    if risk >= BLOCK_RISK:
        return Decision("blocked", [], "Risk too high: payment held for review.")
    if (amount <= LOW_VALUE_LIMIT and risk < MEDIUM_RISK
            and exempt_total + amount <= CUMULATIVE_LIMIT and exempt_count < CUMULATIVE_COUNT):
        return Decision("approved", [], "Low-value, low-risk payment (exempt from step-up).")
    required = ["totp"]
    why = "Strong authentication required"
    if amount >= HIGH_VALUE or risk >= HIGH_RISK:
        required.append("passkey")
        why += " with biometric confirmation (high value or high risk)"
    return Decision("step_up", required, why + ".")

"""Time-based one-time passwords (RFC 6238), implemented with the standard library.

Works with Google Authenticator, Microsoft Authenticator, 1Password, Authy etc.
Each successful code records its time step, so a code cannot be replayed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
from typing import Optional
from urllib.parse import quote

STEP = 30
DIGITS = 6
WINDOW = 1  # accept one step either side for clock drift


def generate_secret() -> str:
    """160-bit random secret, base32 (the RFC 4226 recommended length)."""
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _key(secret_b32: str) -> bytes:
    s = secret_b32.upper().replace(" ", "")
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(key: bytes, counter: int, digits: int = DIGITS, algo=hashlib.sha1) -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), algo).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def code_at(secret_b32: str, t: Optional[float] = None) -> str:
    return hotp(_key(secret_b32), int((time.time() if t is None else t) // STEP))


def verify(secret_b32: str, code: str, last_used_step: int = -1,
           t: Optional[float] = None) -> Optional[int]:
    """Return the matched time step, or None.

    Rejects codes whose step is not newer than ``last_used_step`` (replay).
    Comparison is constant-time.
    """
    code = (code or "").strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    key = _key(secret_b32)
    now_step = int((time.time() if t is None else t) // STEP)
    matched = None
    for step in range(now_step - WINDOW, now_step + WINDOW + 1):
        if hmac.compare_digest(hotp(key, step), code):
            matched = step
    if matched is None or matched <= last_used_step:
        return None
    return matched


def provisioning_uri(secret_b32: str, account: str, issuer: str = "SecurePay 3FA") -> str:
    label = quote(f"{issuer}:{account}")
    return (f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP}")

"""Password hashing with scrypt (Python standard library).

Parameters follow the OWASP Password Storage Cheat Sheet: scrypt with
N=2^15, r=8, p=3 is one of the listed equivalent settings and needs ~32 MB
per hash, which keeps a small free-tier server safe under concurrent logins.
Hashes are self-describing (``scrypt$N$r$p$salt$hash``) so the cost can be
raised later; ``needs_rehash`` tells the caller when to upgrade a stored hash.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

N, R, P = 2 ** 15, 8, 3
DKLEN = 32
SALT_BYTES = 16
MAXMEM = 64 * 1024 * 1024
MIN_LENGTH = 10
MAX_LENGTH = 128

# A short deny-list of the most common passwords (NIST SP 800-63B asks
# verifiers to reject known-compromised and commonly used passwords).
COMMON = {
    "password", "password1", "password12", "password123", "1234567890", "12345678910",
    "qwertyuiop", "qwerty1234", "iloveyou12", "letmein123", "welcome123", "admin12345",
    "abc1234567", "football12", "monkey1234", "dragon1234", "sunshine12", "princess12",
    "passw0rd12", "trustno1234", "1q2w3e4r5t", "qazwsxedcr", "zaq12wsxcde", "baseball12",
    "starwars12", "superman12", "batman1234", "master1234", "changeme12", "p@ssw0rd12",
}


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def validate(password: str, email: str = "") -> list[str]:
    """Return a list of problems (empty if the password is acceptable)."""
    problems = []
    if len(password) < MIN_LENGTH:
        problems.append(f"Use at least {MIN_LENGTH} characters.")
    if len(password) > MAX_LENGTH:
        problems.append(f"Use at most {MAX_LENGTH} characters.")
    lowered = password.lower()
    if lowered in COMMON:
        problems.append("This password is too common.")
    local = email.split("@")[0].lower() if email else ""
    if local and len(local) >= 4 and local in lowered:
        problems.append("Don't include your email name in the password.")
    if len(set(password)) < 4:
        problems.append("Use a less repetitive password.")
    return problems


def hash_password(password: str) -> str:
    salt = os.urandom(SALT_BYTES)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=N, r=R, p=P, dklen=DKLEN, maxmem=MAXMEM)
    return f"scrypt${N}${R}${P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = _unb64(digest)
        actual = hashlib.scrypt(password.encode(), salt=_unb64(salt), n=int(n), r=int(r), p=int(p),
                                dklen=len(expected), maxmem=MAXMEM)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def needs_rehash(stored: str) -> bool:
    try:
        _, n, r, p, *_ = stored.split("$")
        return (int(n), int(r), int(p)) != (N, R, P)
    except ValueError:
        return True


# Burn the same work for unknown accounts so response time does not reveal
# whether an email is registered.
_DUMMY = None


def dummy_verify(password: str) -> None:
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password("dummy-password-for-timing")
    verify_password(password, _DUMMY)

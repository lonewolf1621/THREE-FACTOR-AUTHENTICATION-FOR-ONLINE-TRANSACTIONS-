"""Encryption at rest for authenticator secrets, and token hashing."""
from __future__ import annotations

import hashlib
import logging
import os
import secrets

from cryptography.fernet import Fernet

_key = os.getenv("ENCRYPTION_KEY")
if not _key:
    _key = Fernet.generate_key().decode()
    logging.warning("ENCRYPTION_KEY not set: using a per-process key (demo mode; data resets on restart)")
_fernet = Fernet(_key.encode() if isinstance(_key, str) else _key)


def encrypt(text: str) -> str:
    return _fernet.encrypt(text.encode()).decode()


def decrypt(token: str) -> str:
    return _fernet.decrypt(token.encode()).decode()


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_hash(token: str) -> str:
    """Session tokens are stored hashed, so a database leak does not leak live sessions."""
    return hashlib.sha256(token.encode()).hexdigest()

"""Passkeys (WebAuthn) for the inherence factor.

User verification is REQUIRED, so the authenticator must check the person
(fingerprint, face or device PIN) before signing. Payment challenges are
derived from the payment details, which binds the signature to the exact
amount and payee (PSD2 "dynamic linking").
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import List, Optional

from webauthn import (generate_authentication_options, generate_registration_options,
                      options_to_json, verify_authentication_response,
                      verify_registration_response)
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

RP_NAME = "SecurePay 3FA demo"


def registration_options(rp_id: str, user_handle: bytes, email: str, name: str,
                         existing: List[bytes]) -> tuple[dict, bytes]:
    opts = generate_registration_options(
        rp_id=rp_id, rp_name=RP_NAME, user_id=user_handle, user_name=email, user_display_name=name,
        exclude_credentials=[PublicKeyCredentialDescriptor(id=c) for c in existing],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.PREFERRED),
        timeout=120000,
    )
    return json.loads(options_to_json(opts)), opts.challenge


def verify_registration(credential: dict, challenge: bytes, rp_id: str, origin: str):
    return verify_registration_response(
        credential=json.dumps(credential), expected_challenge=challenge, expected_rp_id=rp_id,
        expected_origin=origin, require_user_verification=True)


def authentication_options(rp_id: str, credential_ids: List[bytes],
                           challenge: Optional[bytes] = None) -> tuple[dict, bytes]:
    opts = generate_authentication_options(
        rp_id=rp_id, challenge=challenge or os.urandom(32),
        allow_credentials=[PublicKeyCredentialDescriptor(id=c) for c in credential_ids],
        user_verification=UserVerificationRequirement.REQUIRED, timeout=120000)
    return json.loads(options_to_json(opts)), opts.challenge


def verify_authentication(credential: dict, challenge: bytes, rp_id: str, origin: str,
                          public_key: bytes, sign_count: int):
    return verify_authentication_response(
        credential=json.dumps(credential), expected_challenge=challenge, expected_rp_id=rp_id,
        expected_origin=origin, credential_public_key=public_key,
        credential_current_sign_count=sign_count, require_user_verification=True)


def payment_challenge(payment_id: str, amount: float, currency: str, payee: str, nonce: bytes) -> bytes:
    """Challenge = SHA-256 over the payment details plus a random nonce."""
    msg = f"{payment_id}|{amount:.2f}|{currency}|{payee}".encode()
    return hashlib.sha256(msg + b"|" + nonce).digest()

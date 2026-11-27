"""Pure-logic tests: password hashing, TOTP (RFC 6238 vectors), risk model and policy."""
import base64
import hashlib

from app import passwords, policy, risk, totp


# ---------- passwords
def test_hash_roundtrip_and_salt():
    h1, h2 = passwords.hash_password("correct horse battery"), passwords.hash_password("correct horse battery")
    assert h1 != h2 and h1.startswith("scrypt$32768$8$3$")
    assert passwords.verify_password("correct horse battery", h1)
    assert not passwords.verify_password("wrong horse battery", h1)
    assert not passwords.verify_password("x", "not-a-hash")
    assert not passwords.needs_rehash(h1) and passwords.needs_rehash("scrypt$16384$8$1$a$b")


def test_password_rules():
    assert passwords.validate("short")
    assert passwords.validate("password123")
    assert passwords.validate("vishal-secret-99", "vishal@example.com")
    assert passwords.validate("aaaaaaaaaaaa")
    assert passwords.validate("blue-Tiger-coffee-42") == []


# ---------- TOTP
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


def test_rfc6238_sha1_vectors():
    # RFC 6238 Appendix B (SHA-1), 8 digits
    key = b"12345678901234567890"
    for t, expected in [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                        (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]:
        assert totp.hotp(key, t // 30, digits=8, algo=hashlib.sha1) == expected


def test_verify_window_and_replay():
    t = 1_700_000_000
    code = totp.code_at(RFC_SECRET, t)
    step = totp.verify(RFC_SECRET, code, t=t)
    assert step == t // 30
    assert totp.verify(RFC_SECRET, code, last_used_step=step, t=t) is None       # replay rejected
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, t - 30), t=t) == step - 1   # drift ok
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, t - 90), t=t) is None      # too old
    assert totp.verify(RFC_SECRET, "12ab56", t=t) is None
    assert totp.verify(RFC_SECRET, "", t=t) is None


def test_secret_and_uri():
    s = totp.generate_secret()
    assert len(base64.b32decode(s + "=" * (-len(s) % 8))) == 20
    uri = totp.provisioning_uri(s, "a@b.com")
    assert uri.startswith("otpauth://totp/SecurePay%203FA%3Aa%40b.com?secret=") and "period=30" in uri


# ---------- risk
def test_known_context_is_low_risk_and_attacker_is_high():
    calm = risk.login_features(device_known=True, network_known=True, hour=10, past_hours=[9, 10, 11],
                               failures_last_hour=0)
    hostile = risk.login_features(device_known=False, network_known=False, hour=22, past_hours=[9, 10, 11],
                                  failures_last_hour=3)
    lo, hi = risk.score("login", calm), risk.score("login", hostile)
    assert lo.score < 0.01 and hi.score > 0.9
    assert lo.reasons == [] and "new device" in hi.reasons and "recent failed attempts" in hi.reasons


def test_hour_distance_wraps_midnight():
    f = risk.login_features(device_known=True, network_known=True, hour=0.5, past_hours=[23, 23.5, 0],
                            failures_last_hour=0)
    assert abs(f["odd_hour"] - 1 / 12) < 1e-9          # one hour from the usual 23:30
    noon = risk.login_features(device_known=True, network_known=True, hour=11.5, past_hours=[23, 23.5, 0],
                               failures_last_hour=0)
    assert noon["odd_hour"] == 1.0


def test_payment_features():
    base = risk.login_features(device_known=True, network_known=True, hour=10, past_hours=[], failures_last_hour=0)
    small = risk.payment_features(base, amount=20, past_amounts=[], payee_known=True, payments_last_hour=0)
    big = risk.payment_features(base, amount=5000, past_amounts=[20, 25, 30], payee_known=False, payments_last_hour=4)
    assert small["amount_ratio"] == 0 and big["amount_ratio"] > 2
    assert risk.score("payment", big).score > risk.score("payment", small).score


# ---------- policy
def test_payment_policy():
    assert policy.payment_decision(20, 0.01, 0, 0).status == "approved"
    assert policy.payment_decision(20, 0.01, 90, 1).required == ["totp"]       # cumulative limit
    assert policy.payment_decision(20, 0.01, 0, 5).required == ["totp"]        # count limit
    assert policy.payment_decision(20, 0.3, 0, 0).required == ["totp"]         # risk overrides exemption
    assert policy.payment_decision(150, 0.01, 0, 0).required == ["totp"]
    assert policy.payment_decision(800, 0.01, 0, 0).required == ["totp", "passkey"]
    assert policy.payment_decision(50, 0.7, 0, 0).required == ["totp", "passkey"]
    assert policy.payment_decision(50, 0.95, 0, 0).status == "blocked"


def test_login_policy():
    assert policy.login_requirements(0.01, False, False) == []
    assert policy.login_requirements(0.01, True, False) == ["totp"]
    assert policy.login_requirements(0.01, True, True) == ["totp"]
    assert policy.login_requirements(0.3, True, True) == ["totp"]
    assert policy.login_requirements(0.7, True, True) == ["totp", "passkey"]
    assert policy.login_requirements(0.3, False, True) == ["passkey"]

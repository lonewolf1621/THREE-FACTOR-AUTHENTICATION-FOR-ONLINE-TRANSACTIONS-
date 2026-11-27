"""End-to-end API tests (FastAPI TestClient). Passkey signatures need a real
authenticator, so passkey tests cover options and the enrolment gate."""
import json
import os
import tempfile

import pytest

os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.sqlite3")
os.environ["DEMO_MODE"] = "true"
os.environ["REGISTER_LIMIT_PER_HOUR"] = "1000"

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from app import db, main, totp  # noqa: E402

PASSWORD = "blue-Tiger-coffee-42"


class Clock:
    t = 1_800_000_000.0

    def time(self):
        return self.t


@pytest.fixture()
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(totp, "time", c)
    return c


def new_client():
    return TestClient(main.app)


def register(c, email, password=PASSWORD):
    return c.post("/api/register", json={"name": "Test User", "email": email, "password": password})


def enrol_totp(c, clock):
    secret = c.post("/api/totp/setup", json={}).json()["secret"]
    r = c.post("/api/totp/confirm", json={"code": totp.code_at(secret, clock.t)})
    assert r.status_code == 200, r.text
    return secret


def test_register_me_and_headers():
    c = new_client()
    r = register(c, "a@example.com")
    assert r.status_code == 200 and r.json()["state"] == "active"
    cookie = r.headers.get("set-cookie", "").lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    me = c.get("/api/me")
    assert me.json()["factors"] == {"password": True, "totp": False, "passkey": False, "passkeys": 0}
    assert "default-src 'self'" in me.headers["content-security-policy"]
    assert me.headers["x-frame-options"] == "DENY" and me.headers["cache-control"] == "no-store"


def test_registration_rules():
    c = new_client()
    assert register(c, "weak@example.com", "password123").status_code == 422
    assert register(c, "not-an-email").status_code == 422
    assert register(c, "dup@example.com").status_code == 200
    assert register(new_client(), "dup@example.com").status_code == 409
    r = c.post("/api/register", data="name=x", headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code in (415, 422)


def test_wrong_password_is_generic_and_locks_after_five():
    register(new_client(), "lock@example.com")
    c = new_client()
    unknown = c.post("/api/login", json={"email": "nobody@example.com", "password": PASSWORD})
    wrong = c.post("/api/login", json={"email": "lock@example.com", "password": "wrong-password-1"})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json()["detail"] == wrong.json()["detail"]
    for _ in range(4):
        c.post("/api/login", json={"email": "lock@example.com", "password": "wrong-password-1"})
    locked = c.post("/api/login", json={"email": "lock@example.com", "password": PASSWORD})
    assert locked.status_code == 423


def test_totp_login_step_up_and_replay(clock):
    c = new_client()
    register(c, "totp@example.com")
    secret = enrol_totp(c, clock)
    c.post("/api/logout", json={})

    clock.t += 30
    r = c.post("/api/login", json={"email": "totp@example.com", "password": PASSWORD})
    assert r.json()["state"] == "pending" and r.json()["required"] == ["totp"]
    assert c.get("/api/payments").status_code == 401             # not signed in until the code is given
    code = totp.code_at(secret, clock.t)
    assert c.post("/api/login/totp", json={"code": "000000"}).status_code == 401
    assert c.post("/api/login/totp", json={"code": code}).json()["state"] == "active"
    assert c.get("/api/payments").status_code == 200

    c.post("/api/logout", json={})
    c.post("/api/login", json={"email": "totp@example.com", "password": PASSWORD})
    assert c.post("/api/login/totp", json={"code": code}).status_code == 401   # same code cannot be replayed


def test_payments_exemption_step_up_and_enrolment_gate(clock):
    c = new_client()
    register(c, "pay@example.com")
    small = c.post("/api/payments", json={"payee": "Coffee shop", "amount": 20}).json()
    assert small["status"] == "approved"
    gated = c.post("/api/payments", json={"payee": "Landlord", "amount": 150}).json()
    assert gated["status"] == "needs_enrolment"

    secret = enrol_totp(c, clock)
    p = c.post("/api/payments", json={"payee": "Landlord", "amount": 150}).json()
    assert p["status"] == "step_up" and p["required"] == ["totp"]
    clock.t += 30
    done = c.post(f"/api/payments/{p['id']}/totp", json={"code": totp.code_at(secret, clock.t)}).json()
    assert done["status"] == "approved"

    big = c.post("/api/payments", json={"payee": "Car dealer", "amount": 800}).json()
    assert big["status"] == "needs_enrolment" and "passkey" in big["reason"]


def test_low_value_exemption_limits(clock):
    c = new_client()
    register(c, "limits@example.com")
    enrol_totp(c, clock)
    statuses = [c.post("/api/payments", json={"payee": "Corner shop", "amount": 20}).json()["status"]
                for _ in range(6)]
    assert statuses[:5] == ["approved"] * 5 and statuses[5] == "step_up"   # 5 payments / 100 cumulative


def test_simulated_attacker_is_blocked_and_audited(clock):
    c = new_client()
    register(c, "risk@example.com")
    r = c.post("/api/payments", json={"payee": "Unknown crypto exchange", "amount": 150},
               headers={"x-demo-signals": "new_device,new_network,odd_hour,failures"}).json()
    assert r["status"] == "blocked" and r["risk"]["level"] == "high"
    assert "new device" in r["risk"]["reasons"]
    events = c.get("/api/activity").json()["events"]
    assert any(e["type"] == "payment_blocked" and e["detail"]["simulated"] for e in events)


def test_audit_log_never_contains_secrets(clock):
    c = new_client()
    register(c, "audit@example.com")
    secret = enrol_totp(c, clock)
    blob = json.dumps(c.get("/api/activity").json())
    assert PASSWORD not in blob and secret not in blob
    row = db.q1("SELECT totp_secret_enc, password_hash FROM users WHERE email='audit@example.com'")
    assert secret not in row["totp_secret_enc"] and PASSWORD not in row["password_hash"]


def test_passkey_registration_options():
    c = new_client()
    register(c, "pk@example.com")
    o = c.post("/api/passkey/register/options", json={}).json()
    assert o["rp"]["id"] == "testserver" and o["authenticatorSelection"]["userVerification"] == "required"
    assert len(o["challenge"]) >= 40
    bad = c.post("/api/passkey/register/verify", json={"credential": {"id": "x", "rawId": "x", "type": "public-key",
                                                                      "response": {}}})
    assert bad.status_code == 400


def test_health():
    assert new_client().get("/health").json()["status"] == "ok"

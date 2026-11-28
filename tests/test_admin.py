"""Owner admin: role from ADMIN_EMAILS, three-factor gate, user management, audit, settings."""
import os
import tempfile

import pytest

os.environ.setdefault("DB_PATH", os.path.join(tempfile.mkdtemp(), "test.sqlite3"))
os.environ.setdefault("REGISTER_LIMIT_PER_HOUR", "1000")
pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from app import db, main, totp  # noqa: E402

PASSWORD = "blue-Tiger-coffee-42"
ADMIN = "owner@example.com"


@pytest.fixture(autouse=True)
def admin_env(monkeypatch):
    monkeypatch.setattr(main, "ADMIN_EMAILS", (ADMIN,))
    db.set_settings(db.DEFAULT_SETTINGS)
    yield
    db.set_settings(db.DEFAULT_SETTINGS)


def make_admin_session(c, monkeypatch):
    """Admin who has signed in with all three factors (passkey verification is stubbed:
    a real signature needs a hardware authenticator)."""
    if not db.q1("SELECT 1 FROM users WHERE email=?", (ADMIN,)):
        c.post("/api/register", json={"name": "Owner", "email": ADMIN, "password": PASSWORD})
    uid = db.q1("SELECT id FROM users WHERE email=?", (ADMIN,))["id"]
    token = main.crypto.new_token()
    now = __import__("time").time()
    db.run("INSERT INTO sessions (token_hash, user_id, created, last_seen, state, required, satisfied) "
           "VALUES (?,?,?,?,?,?,?)", (main.crypto.token_hash(token), uid, now, now, "active",
                                     '["password","totp","passkey"]', '["passkey","password","totp"]'))
    c.cookies.set("sid", token)
    return uid


def user(c, email):
    r = c.post("/api/register", json={"name": "U", "email": email, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return db.q1("SELECT id FROM users WHERE email=?", (email,))["id"]


def test_non_admin_and_password_only_admin_are_refused():
    c = TestClient(main.app)
    user(c, "plain@example.com")
    assert c.get("/api/admin/stats").status_code == 403
    a = TestClient(main.app)
    if not db.q1("SELECT 1 FROM users WHERE email=?", (ADMIN,)):
        a.post("/api/register", json={"name": "Owner", "email": ADMIN, "password": PASSWORD})
    else:
        a.post("/api/login", json={"email": ADMIN, "password": PASSWORD})
    me = a.get("/api/me").json()
    assert me["is_admin"] is True and me["admin_ready"] is False
    r = a.get("/api/admin/stats")
    assert r.status_code == 403 and "passkey" in r.json()["detail"]


def test_admin_login_always_requires_code_and_passkey(monkeypatch):
    c = TestClient(main.app)
    uid = make_admin_session(c, monkeypatch)
    db.run("UPDATE users SET totp_secret_enc=? WHERE id=?", (main.crypto.encrypt(totp.generate_secret()), uid))
    db.run("INSERT OR IGNORE INTO passkeys (user_id, credential_id, public_key, sign_count, created) VALUES (?,?,?,?,?)",
           (uid, b"cred-" + str(uid).encode(), b"pk", 0, 0))
    fresh = TestClient(main.app)
    r = fresh.post("/api/login", json={"email": ADMIN, "password": PASSWORD}).json()
    assert r["state"] == "pending" and r["required"] == ["totp", "passkey"]


def test_admin_stats_users_suspend_unlock_delete(monkeypatch):
    a = TestClient(main.app)
    make_admin_session(a, monkeypatch)
    u = TestClient(main.app)
    uid = user(u, "victim@example.com")
    stats = a.get("/api/admin/stats").json()
    assert stats["users"]["total"] >= 2 and "risk_bands" in stats["payments"]
    rows = a.get("/api/admin/users").json()["users"]
    assert any(r["email"] == "victim@example.com" and r["status"] == "active" for r in rows)
    assert all("password" not in str(r) and "totp_secret" not in str(r) for r in rows)

    assert a.post(f"/api/admin/users/{uid}/suspend", json={}).status_code == 200
    assert u.get("/api/me").status_code == 401                       # their session was ended
    assert TestClient(main.app).post("/api/login", json={"email": "victim@example.com", "password": PASSWORD}).status_code == 403
    assert a.post(f"/api/admin/users/{uid}/unlock", json={}).status_code == 200
    assert TestClient(main.app).post("/api/login", json={"email": "victim@example.com", "password": PASSWORD}).status_code == 200

    admin_id = db.q1("SELECT id FROM users WHERE email=?", (ADMIN,))["id"]
    assert a.post(f"/api/admin/users/{admin_id}/suspend", json={}).status_code == 409   # cannot lock yourself out
    assert a.delete(f"/api/admin/users/{uid}").status_code == 200
    assert db.q1("SELECT 1 FROM users WHERE id=?", (uid,)) is None

    audit = a.get("/api/admin/audit?type=admin").json()["events"]
    kinds = {e["type"] for e in audit}
    assert {"admin_suspended_user", "admin_unlocked_user", "admin_deleted_user"} <= kinds


def test_settings_close_registration_pause_payments_and_banner(monkeypatch):
    a = TestClient(main.app)
    make_admin_session(a, monkeypatch)
    u = TestClient(main.app)
    user(u, "before@example.com")
    r = a.put("/api/admin/settings", json={"maintenance_banner": "Upgrade at 6pm", "registration_open": False,
                                           "payments_enabled": False, "demo_signals_enabled": False})
    assert r.status_code == 200 and r.json()["registration_open"] is False
    st = TestClient(main.app).get("/api/status").json()
    assert st["maintenance_banner"] == "Upgrade at 6pm" and st["demo_signals_enabled"] is False
    closed = TestClient(main.app).post("/api/register", json={"name": "N", "email": "new@example.com", "password": PASSWORD})
    assert closed.status_code == 503
    assert u.post("/api/payments", json={"payee": "Shop", "amount": 5}).status_code == 503


def test_clear_demo_data_keeps_admin(monkeypatch):
    a = TestClient(main.app)
    make_admin_session(a, monkeypatch)
    user(TestClient(main.app), "temp1@example.com")
    assert a.post("/api/admin/clear-demo-data", json={}).status_code == 422
    r = a.post("/api/admin/clear-demo-data?confirm=DELETE", json={})
    assert r.status_code == 200 and r.json()["accounts_removed"] >= 1
    emails = [x["email"] for x in a.get("/api/admin/users").json()["users"]]
    assert emails == [ADMIN]

"""SecurePay 3FA: risk-based three-factor authentication for online payments.

Factors: password (knowledge), authenticator-app code (possession) and a
passkey with fingerprint/face verification (inherence). A risk model decides
how many factors each login and payment needs.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from webauthn.helpers import base64url_to_bytes

from app import crypto, db, passkeys, passwords, policy, risk, totp

logging.basicConfig(level=logging.INFO)
STATIC = os.path.join(os.path.dirname(__file__), "static")
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
SESSION_COOKIE, DEVICE_COOKIE = "sid", "did"
SESSION_IDLE = 30 * 60
LOCK_AFTER, LOCK_SECONDS = 5, 15 * 60
MAX_CODE_ATTEMPTS = 5
PAYMENT_TTL = 5 * 60
REGISTER_LIMIT = int(os.getenv("REGISTER_LIMIT_PER_HOUR", "10"))
ADMIN_EMAILS = tuple(e.strip().lower() for e in os.getenv("ADMIN_EMAILS", "").split(",") if e.strip())
LOCKED_FOREVER = 9e15  # "locked_until" value for accounts suspended by an admin
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,24}$")

@asynccontextmanager
async def lifespan(_app):
    db.connect()
    db.prune(ADMIN_EMAILS)
    yield


app = FastAPI(title="SecurePay 3FA", version="1.0.0", lifespan=lifespan,
              description="Risk-based three-factor authentication for online payments (demo).")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


# ---------------------------------------------------------------- helpers
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    if not request.url.path.startswith(("/docs", "/redoc")):  # Swagger UI loads its assets from a CDN
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if _scheme(request) == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def _scheme(request: Request) -> str:
    return request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0].strip()


def origin_and_rp(request: Request) -> tuple[str, str]:
    configured = os.getenv("APP_ORIGIN")
    if configured:
        origin = configured.rstrip("/")
    else:
        host = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost"))
        origin = f"{_scheme(request)}://{host}"
    rp_id = origin.split("://", 1)[1].split(":")[0]
    return origin, rp_id


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")


def network_of(ip: str) -> str:
    """Coarse network (IPv4 /24, IPv6 /48): enough to spot a new network, without storing the IP."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def device_id(request: Request) -> str:
    did = request.cookies.get(DEVICE_COOKIE, "")
    return did if re.fullmatch(r"[A-Za-z0-9_-]{20,64}", did) else ""


def demo_enabled() -> bool:
    return DEMO_MODE and db.get_settings()["demo_signals_enabled"]


def is_admin(user) -> bool:
    return bool(user) and user["email"] in ADMIN_EMAILS


def demo_signals(request: Request) -> List[str]:
    if not demo_enabled():
        return []
    raw = request.headers.get("x-demo-signals", "")
    return [s for s in raw.split(",") if s in {"new_device", "new_network", "odd_hour", "failures"}]


def apply_demo(features: dict, signals: List[str]) -> dict:
    f = dict(features)
    if "new_device" in signals:
        f["new_device"] = 1.0
    if "new_network" in signals:
        f["new_network"] = 1.0
    if "odd_hour" in signals:
        f["odd_hour"] = max(f["odd_hour"], 0.85)
    if "failures" in signals:
        f["recent_failures"] = max(f["recent_failures"], 0.6)
    return f


def rate_limit(key: str, limit: int, window: int) -> None:
    now = time.time()
    count = db.q1("SELECT COUNT(*) AS n FROM rate WHERE key = ? AND ts > ?", (key, now - window))["n"]
    if count >= limit:
        raise HTTPException(status_code=429, detail="Too many attempts. Please wait and try again.")
    db.run("INSERT INTO rate (key, ts) VALUES (?, ?)", (key, now))


def set_cookie(response: Response, request: Request, name: str, value: str, max_age: int) -> None:
    response.set_cookie(name, value, max_age=max_age, httponly=True, samesite="strict",
                        secure=_scheme(request) == "https", path="/")


def hour_now() -> float:
    now = datetime.now(timezone.utc)
    return now.hour + now.minute / 60


def enrolled(user) -> dict:
    n_keys = db.q1("SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?", (user["id"],))["n"]
    return {"password": True, "totp": bool(user["totp_secret_enc"]), "passkey": n_keys > 0,
            "passkeys": n_keys}


def require_json(request: Request) -> None:
    """Simple CSRF defence on top of SameSite=Strict cookies: state-changing calls must be JSON."""
    if not request.headers.get("content-type", "").startswith("application/json"):
        raise HTTPException(status_code=415, detail="Send JSON")


def current_session(request: Request, active: bool = True):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Not signed in")
    s = db.q1("SELECT * FROM sessions WHERE token_hash = ?", (crypto.token_hash(token),))
    if not s or time.time() - s["last_seen"] > SESSION_IDLE:
        raise HTTPException(status_code=401, detail="Session expired")
    if active and s["state"] != "active":
        raise HTTPException(status_code=401, detail="Sign-in not complete")
    db.run("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (time.time(), s["token_hash"]))
    user = db.q1("SELECT * FROM users WHERE id = ?", (s["user_id"],))
    if not user:
        raise HTTPException(status_code=401, detail="Account no longer exists")
    if user["locked_until"] >= LOCKED_FOREVER:
        raise HTTPException(status_code=403, detail="This account is suspended")
    return s, user


def active_session(request: Request):
    return current_session(request, active=True)


def login_risk(request: Request, user) -> risk.Risk:
    uid = user["id"]
    did = device_id(request)
    net = network_of(client_ip(request))
    known_dev = bool(did) and db.q1("SELECT 1 FROM devices WHERE user_id=? AND device_id=?", (uid, did)) is not None
    known_net = db.q1("SELECT 1 FROM networks WHERE user_id=? AND network=?", (uid, net)) is not None
    hours = [r["hour"] for r in db.q("SELECT hour FROM logins WHERE user_id=? ORDER BY ts DESC LIMIT 50", (uid,))]
    fails = db.q1("SELECT COUNT(*) AS n FROM events WHERE user_id=? AND ts>? AND type IN "
                  "('login_failed','totp_failed','passkey_failed')", (uid, time.time() - 3600))["n"]
    feats = risk.login_features(device_known=known_dev, network_known=known_net, hour=hour_now(),
                                past_hours=hours, failures_last_hour=fails)
    return risk.score("login", apply_demo(feats, demo_signals(request)))


def remember_device(request: Request, response: Response, uid: int) -> str:
    did = device_id(request) or crypto.new_token(24)
    set_cookie(response, request, DEVICE_COOKIE, did, 365 * 86400)
    now = time.time()
    db.run("INSERT OR IGNORE INTO devices (user_id, device_id, first_seen) VALUES (?,?,?)", (uid, did, now))
    db.run("INSERT OR IGNORE INTO networks (user_id, network, first_seen) VALUES (?,?,?)",
           (uid, network_of(client_ip(request)), now))
    return did


def ctx(request: Request) -> dict:
    return {"network": network_of(client_ip(request)), "device": device_id(request)}


# ---------------------------------------------------------------- models
class Register(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    email: str = Field(..., max_length=254)
    password: str = Field(..., max_length=128)


class Login(BaseModel):
    email: str = Field(..., max_length=254)
    password: str = Field(..., max_length=128)


class Code(BaseModel):
    code: str = Field(..., max_length=10)


class Credential(BaseModel):
    credential: dict
    label: Optional[str] = Field(None, max_length=60)


class PaymentIn(BaseModel):
    payee: str = Field(..., min_length=2, max_length=80)
    amount: float = Field(..., gt=0, le=1_000_000)
    currency: str = Field("GBP", pattern="^(GBP|EUR|USD|INR)$")


# ---------------------------------------------------------------- pages
@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.api_route("/health", methods=["GET", "HEAD"])
def health():
    db.q1("SELECT 1 AS ok")
    return {"status": "ok", "demo_mode": demo_enabled(), "risk_model": risk.MODEL.get("_note", "")}


@app.get("/api/status")
def public_status():
    """Public: maintenance banner and which features are open."""
    st = db.get_settings()
    return {"maintenance_banner": st["maintenance_banner"], "registration_open": st["registration_open"],
            "payments_enabled": st["payments_enabled"], "demo_signals_enabled": demo_enabled()}


# ---------------------------------------------------------------- account
@app.post("/api/register")
def register(body: Register, request: Request, response: Response):
    require_json(request)
    st = db.get_settings()
    if not st["registration_open"] and body.email.strip().lower() not in ADMIN_EMAILS:
        raise HTTPException(status_code=503, detail=st["maintenance_banner"] or "Registration is closed right now.")
    rate_limit(f"register:{network_of(client_ip(request))}", REGISTER_LIMIT, 3600)
    email = body.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    problems = passwords.validate(body.password, email)
    if problems:
        raise HTTPException(status_code=422, detail=" ".join(problems))
    if db.q1("SELECT 1 FROM users WHERE email = ?", (email,)):
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    cur = db.run("INSERT INTO users (email, name, password_hash, created, webauthn_user_id) VALUES (?,?,?,?,?)",
                 (email, body.name.strip(), passwords.hash_password(body.password), time.time(), os.urandom(32)))
    uid = cur.lastrowid
    did = remember_device(request, response, uid)
    _start_session(request, response, uid, "active", ["password"], ["password"], did, None)
    db.run("INSERT INTO logins (user_id, ts, hour) VALUES (?,?,?)", (uid, time.time(), hour_now()))
    db.log_event(uid, "account_created", **ctx(request))
    return {"state": "active", "required": []}


def _start_session(request, response, uid, state, required, satisfied, did, r) -> str:
    token = crypto.new_token()
    now = time.time()
    db.run("INSERT INTO sessions (token_hash, user_id, created, last_seen, state, required, satisfied, "
           "device_id, network, risk) VALUES (?,?,?,?,?,?,?,?,?,?)",
           (crypto.token_hash(token), uid, now, now, state, json.dumps(required), json.dumps(satisfied),
            did, network_of(client_ip(request)), json.dumps(r.as_dict()) if r else None))
    set_cookie(response, request, SESSION_COOKIE, token, SESSION_IDLE)
    return token


@app.post("/api/login")
def login(body: Login, request: Request, response: Response):
    require_json(request)
    ip_net = network_of(client_ip(request))
    rate_limit(f"login-ip:{ip_net}", 30, 900)
    email = body.email.strip().lower()
    rate_limit(f"login-email:{email}", 10, 900)
    user = db.q1("SELECT * FROM users WHERE email = ?", (email,))
    generic = HTTPException(status_code=401, detail="Email or password is incorrect")
    if not user:
        passwords.dummy_verify(body.password)
        raise generic
    if user["locked_until"] >= LOCKED_FOREVER:
        passwords.dummy_verify(body.password)
        db.log_event(user["id"], "login_blocked_suspended", **ctx(request))
        raise HTTPException(status_code=403, detail="This account is suspended. Contact the administrator.")
    if user["locked_until"] > time.time():
        db.log_event(user["id"], "login_blocked_locked", **ctx(request))
        raise HTTPException(status_code=423, detail="Too many failed attempts. Try again in 15 minutes.")
    if not passwords.verify_password(body.password, user["password_hash"]):
        failed = user["failed_count"] + 1
        locked = time.time() + LOCK_SECONDS if failed >= LOCK_AFTER else 0
        db.run("UPDATE users SET failed_count=?, locked_until=? WHERE id=?",
               (0 if locked else failed, locked, user["id"]))
        db.log_event(user["id"], "login_failed", **ctx(request), locked=bool(locked))
        raise generic
    db.run("UPDATE users SET failed_count=0 WHERE id=?", (user["id"],))
    if passwords.needs_rehash(user["password_hash"]):
        db.run("UPDATE users SET password_hash=? WHERE id=?", (passwords.hash_password(body.password), user["id"]))

    r = login_risk(request, user)
    has = enrolled(user)
    required = policy.login_requirements(r.score, has["totp"], has["passkey"])
    if is_admin(user) and has["totp"] and has["passkey"]:
        required = ["totp", "passkey"]  # admins always prove all three factors
    state = "pending" if required else "active"
    did = device_id(request)
    _start_session(request, response, user["id"], state, ["password"] + required, ["password"], did, r)
    db.log_event(user["id"], "password_ok", **ctx(request), risk=round(r.score, 3), needs=required,
                 simulated=demo_signals(request))
    if state == "active":
        _activated(request, response, user["id"], ["password"])
    return {"state": state, "required": required, "risk": r.as_dict()}


def _activated(request: Request, response: Response, uid: int, factors: List[str]) -> None:
    remember_device(request, response, uid)
    db.run("INSERT INTO logins (user_id, ts, hour) VALUES (?,?,?)", (uid, time.time(), hour_now()))
    db.log_event(uid, "login_success", **ctx(request), factors=factors)
    if len(factors) >= 2:  # strong customer authentication completed: resets the low-value exemption counter
        db.log_event(uid, "sca_completed", **ctx(request), factors=factors)


def _satisfy(session, factor: str, request: Request, response: Response) -> dict:
    satisfied = sorted(set(json.loads(session["satisfied"]) + [factor]))
    required = json.loads(session["required"])
    done = set(required) <= set(satisfied)
    db.run("UPDATE sessions SET satisfied=?, state=?, attempts=0, challenge=NULL WHERE token_hash=?",
           (json.dumps(satisfied), "active" if done else "pending", session["token_hash"]))
    if done:
        _activated(request, response, session["user_id"], satisfied)
    return {"state": "active" if done else "pending",
            "required": [f for f in required if f not in satisfied]}


def _check_totp(user, code: str) -> bool:
    if not user["totp_secret_enc"]:
        return False
    step = totp.verify(crypto.decrypt(user["totp_secret_enc"]), code, user["totp_last_step"])
    if step is None:
        return False
    db.run("UPDATE users SET totp_last_step=? WHERE id=?", (step, user["id"]))
    return True


@app.post("/api/login/totp")
def login_totp(body: Code, request: Request, response: Response):
    require_json(request)
    s, user = current_session(request, active=False)
    if "totp" not in json.loads(s["required"]) or s["state"] != "pending":
        raise HTTPException(status_code=400, detail="No authenticator code needed")
    if s["attempts"] >= MAX_CODE_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many wrong codes. Sign in again.")
    if not _check_totp(user, body.code):
        db.run("UPDATE sessions SET attempts=attempts+1 WHERE token_hash=?", (s["token_hash"],))
        db.log_event(user["id"], "totp_failed", **ctx(request))
        raise HTTPException(status_code=401, detail="That code is not valid")
    db.log_event(user["id"], "totp_ok", **ctx(request))
    return _satisfy(s, "totp", request, response)


def _user_credentials(uid: int) -> List[bytes]:
    return [r["credential_id"] for r in db.q("SELECT credential_id FROM passkeys WHERE user_id=?", (uid,))]


@app.post("/api/login/passkey/options")
def login_passkey_options(request: Request):
    require_json(request)
    s, user = current_session(request, active=False)
    if "passkey" not in json.loads(s["required"]) or s["state"] != "pending":
        raise HTTPException(status_code=400, detail="No passkey needed")
    _, rp_id = origin_and_rp(request)
    options, challenge = passkeys.authentication_options(rp_id, _user_credentials(user["id"]))
    db.run("UPDATE sessions SET challenge=? WHERE token_hash=?", (challenge, s["token_hash"]))
    return options


def _verify_passkey(user, credential: dict, challenge: Optional[bytes], request: Request) -> bool:
    if not challenge:
        return False
    try:
        cred_id = base64url_to_bytes(credential.get("rawId") or credential.get("id", ""))
    except Exception:
        return False
    row = db.q1("SELECT * FROM passkeys WHERE user_id=? AND credential_id=?", (user["id"], cred_id))
    if not row:
        return False
    origin, rp_id = origin_and_rp(request)
    try:
        result = passkeys.verify_authentication(credential, challenge, rp_id, origin,
                                                row["public_key"], row["sign_count"])
    except Exception as e:  # invalid signature, wrong origin, UV not performed, ...
        logging.info("passkey verification failed: %s", type(e).__name__)
        return False
    db.run("UPDATE passkeys SET sign_count=? WHERE id=?", (result.new_sign_count, row["id"]))
    return True


@app.post("/api/login/passkey/verify")
def login_passkey_verify(body: Credential, request: Request, response: Response):
    require_json(request)
    s, user = current_session(request, active=False)
    if "passkey" not in json.loads(s["required"]) or s["state"] != "pending":
        raise HTTPException(status_code=400, detail="No passkey needed")
    if not _verify_passkey(user, body.credential, s["challenge"], request):
        db.run("UPDATE sessions SET attempts=attempts+1, challenge=NULL WHERE token_hash=?", (s["token_hash"],))
        db.log_event(user["id"], "passkey_failed", **ctx(request))
        raise HTTPException(status_code=401, detail="Passkey check failed")
    db.log_event(user["id"], "passkey_ok", **ctx(request))
    return _satisfy(s, "passkey", request, response)


@app.post("/api/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        db.run("DELETE FROM sessions WHERE token_hash=?", (crypto.token_hash(token),))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@app.get("/api/me")
def me(request: Request):
    s, user = current_session(request, active=False)
    return {"name": user["name"], "email": user["email"], "state": s["state"],
            "factors": enrolled(user), "session_factors": json.loads(s["satisfied"]),
            "pending": [f for f in json.loads(s["required"]) if f not in json.loads(s["satisfied"])],
            "login_risk": json.loads(s["risk"]) if s["risk"] else None, "demo_mode": demo_enabled(),
            "is_admin": is_admin(user), "admin_ready": _admin_ready(s, user)}


# ---------------------------------------------------------------- enrolment
@app.post("/api/totp/setup")
def totp_setup(request: Request, sess=Depends(active_session)):
    require_json(request)
    _, user = sess
    secret = totp.generate_secret()
    db.run("UPDATE users SET totp_pending_enc=? WHERE id=?", (crypto.encrypt(secret), user["id"]))
    uri = totp.provisioning_uri(secret, user["email"])
    import base64

    import qrcode
    import qrcode.image.svg
    svg = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=8).to_string()
    return {"secret": secret, "otpauth_uri": uri,
            "qr_svg_data_url": "data:image/svg+xml;base64," + base64.b64encode(svg).decode()}


@app.post("/api/totp/confirm")
def totp_confirm(body: Code, request: Request, sess=Depends(active_session)):
    require_json(request)
    s, user = sess
    if not user["totp_pending_enc"]:
        raise HTTPException(status_code=400, detail="Start set-up first")
    rate_limit(f"totp-confirm:{user['id']}", 10, 900)
    secret = crypto.decrypt(user["totp_pending_enc"])
    step = totp.verify(secret, body.code)
    if step is None:
        raise HTTPException(status_code=401, detail="That code is not valid. Check the time on your phone.")
    db.run("UPDATE users SET totp_secret_enc=?, totp_pending_enc=NULL, totp_last_step=? WHERE id=?",
           (user["totp_pending_enc"], step, user["id"]))
    db.log_event(user["id"], "totp_enrolled", **ctx(request))
    return {"ok": True}


@app.post("/api/passkey/register/options")
def passkey_register_options(request: Request, sess=Depends(active_session)):
    require_json(request)
    s, user = sess
    _, rp_id = origin_and_rp(request)
    options, challenge = passkeys.registration_options(rp_id, user["webauthn_user_id"], user["email"],
                                                       user["name"], _user_credentials(user["id"]))
    db.run("UPDATE sessions SET challenge=? WHERE token_hash=?", (challenge, s["token_hash"]))
    return options


@app.post("/api/passkey/register/verify")
def passkey_register_verify(body: Credential, request: Request, sess=Depends(active_session)):
    require_json(request)
    s, user = sess
    if not s["challenge"]:
        raise HTTPException(status_code=400, detail="Start passkey set-up first")
    origin, rp_id = origin_and_rp(request)
    try:
        v = passkeys.verify_registration(body.credential, s["challenge"], rp_id, origin)
    except Exception as e:
        logging.info("passkey registration failed: %s", type(e).__name__)
        raise HTTPException(status_code=400, detail="Could not verify the passkey")
    finally:
        db.run("UPDATE sessions SET challenge=NULL WHERE token_hash=?", (s["token_hash"],))
    db.run("INSERT INTO passkeys (user_id, credential_id, public_key, sign_count, created, label) "
           "VALUES (?,?,?,?,?,?)", (user["id"], v.credential_id, v.credential_public_key, v.sign_count,
                                     time.time(), (body.label or "Passkey")[:60]))
    db.log_event(user["id"], "passkey_enrolled", **ctx(request))
    return {"ok": True}


# ---------------------------------------------------------------- payments
def _last_sca(uid: int) -> float:
    a = db.q1("SELECT MAX(created) AS t FROM payments WHERE user_id=? AND status='approved' AND exempt=0", (uid,))["t"] or 0
    b = db.q1("SELECT MAX(ts) AS t FROM events WHERE user_id=? AND type='sca_completed'", (uid,))["t"] or 0
    return max(a, b)


def _payment_out(p) -> dict:
    return {"id": p["id"], "payee": p["payee"], "amount": p["amount"], "currency": p["currency"],
            "status": p["status"], "required": [f for f in json.loads(p["required"])
                                                if f not in json.loads(p["satisfied"])],
            "risk": json.loads(p["risk"]), "reason": p["reason"],
            "created": datetime.fromtimestamp(p["created"], timezone.utc).isoformat(timespec="seconds")}


@app.post("/api/payments")
def create_payment(body: PaymentIn, request: Request, sess=Depends(active_session)):
    require_json(request)
    s, user = sess
    uid = user["id"]
    st = db.get_settings()
    if not st["payments_enabled"]:
        raise HTTPException(status_code=503, detail=st["maintenance_banner"] or "Payments are paused right now.")
    rate_limit(f"payments:{uid}", 30, 3600)
    payee = " ".join(body.payee.split())
    base = login_risk(request, user).features
    past = [r["amount"] for r in db.q("SELECT amount FROM payments WHERE user_id=? AND status='approved' "
                                     "ORDER BY created DESC LIMIT 50", (uid,))]
    known_payee = db.q1("SELECT 1 FROM payments WHERE user_id=? AND status='approved' AND lower(payee)=lower(?)",
                        (uid, payee)) is not None
    recent = db.q1("SELECT COUNT(*) AS n FROM payments WHERE user_id=? AND created>?", (uid, time.time() - 3600))["n"]
    feats = risk.payment_features(base, amount=body.amount, past_amounts=past, payee_known=known_payee,
                                  payments_last_hour=recent)
    r = risk.score("payment", feats)
    since = _last_sca(uid)
    ex = db.q1("SELECT COALESCE(SUM(amount),0) AS total, COUNT(*) AS n FROM payments WHERE user_id=? "
               "AND exempt=1 AND status='approved' AND created>?", (uid, since))
    d = policy.payment_decision(body.amount, r.score, ex["total"], ex["n"])
    has = enrolled(user)
    missing = [f for f in d.required if not has[f]]
    status = d.status
    reason = d.reason
    if status == "step_up" and missing:
        status = "needs_enrolment"
        names = {"totp": "an authenticator app", "passkey": "a passkey (fingerprint or face)"}
        reason += " Set up " + " and ".join(names[m] for m in missing) + " to make this payment."
    pid = uuid.uuid4().hex[:16]
    db.run("INSERT INTO payments (id, user_id, created, payee, amount, currency, status, required, satisfied, "
           "risk, reason, exempt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
           (pid, uid, time.time(), payee, round(body.amount, 2), body.currency, status, json.dumps(d.required),
            "[]", json.dumps(r.as_dict()), reason, 1 if status == "approved" else 0))
    db.log_event(uid, f"payment_{status}", **ctx(request), payment=pid, amount=round(body.amount, 2),
                 currency=body.currency, risk=round(r.score, 3), simulated=demo_signals(request))
    return _payment_out(db.q1("SELECT * FROM payments WHERE id=?", (pid,)))


def _pending_payment(pid: str, uid: int):
    p = db.q1("SELECT * FROM payments WHERE id=? AND user_id=?", (pid, uid))
    if not p:
        raise HTTPException(status_code=404, detail="Payment not found")
    if p["status"] != "step_up":
        raise HTTPException(status_code=409, detail=f"Payment is {p['status']}")
    if time.time() - p["created"] > PAYMENT_TTL:
        db.run("UPDATE payments SET status='expired' WHERE id=?", (pid,))
        raise HTTPException(status_code=410, detail="Payment expired. Start again.")
    if p["attempts"] >= MAX_CODE_ATTEMPTS:
        db.run("UPDATE payments SET status='failed' WHERE id=?", (pid,))
        raise HTTPException(status_code=429, detail="Too many failed attempts. Payment cancelled.")
    return p


def _payment_satisfy(p, factor: str, request: Request) -> dict:
    satisfied = sorted(set(json.loads(p["satisfied"]) + [factor]))
    done = set(json.loads(p["required"])) <= set(satisfied)
    db.run("UPDATE payments SET satisfied=?, status=?, attempts=0, challenge=NULL WHERE id=?",
           (json.dumps(satisfied), "approved" if done else "step_up", p["id"]))
    if done:
        db.log_event(p["user_id"], "payment_approved", **ctx(request), payment=p["id"],
                     amount=p["amount"], currency=p["currency"], factors=satisfied)
    return _payment_out(db.q1("SELECT * FROM payments WHERE id=?", (p["id"],)))


@app.post("/api/payments/{pid}/totp")
def payment_totp(pid: str, body: Code, request: Request, sess=Depends(active_session)):
    require_json(request)
    _, user = sess
    p = _pending_payment(pid, user["id"])
    if "totp" not in json.loads(p["required"]):
        raise HTTPException(status_code=400, detail="No code needed for this payment")
    if not _check_totp(user, body.code):
        db.run("UPDATE payments SET attempts=attempts+1 WHERE id=?", (pid,))
        db.log_event(user["id"], "totp_failed", **ctx(request), payment=pid)
        raise HTTPException(status_code=401, detail="That code is not valid")
    return _payment_satisfy(p, "totp", request)


@app.post("/api/payments/{pid}/passkey/options")
def payment_passkey_options(pid: str, request: Request, sess=Depends(active_session)):
    require_json(request)
    _, user = sess
    p = _pending_payment(pid, user["id"])
    if "passkey" not in json.loads(p["required"]):
        raise HTTPException(status_code=400, detail="No passkey needed for this payment")
    challenge = passkeys.payment_challenge(p["id"], p["amount"], p["currency"], p["payee"], os.urandom(16))
    _, rp_id = origin_and_rp(request)
    options, _ = passkeys.authentication_options(rp_id, _user_credentials(user["id"]), challenge)
    db.run("UPDATE payments SET challenge=? WHERE id=?", (challenge, pid))
    return options


@app.post("/api/payments/{pid}/passkey/verify")
def payment_passkey_verify(pid: str, body: Credential, request: Request, sess=Depends(active_session)):
    require_json(request)
    _, user = sess
    p = _pending_payment(pid, user["id"])
    if not _verify_passkey(user, body.credential, p["challenge"], request):
        db.run("UPDATE payments SET attempts=attempts+1, challenge=NULL WHERE id=?", (pid,))
        db.log_event(user["id"], "passkey_failed", **ctx(request), payment=pid)
        raise HTTPException(status_code=401, detail="Passkey check failed")
    return _payment_satisfy(p, "passkey", request)


@app.get("/api/payments")
def list_payments(sess=Depends(active_session)):
    _, user = sess
    rows = db.q("SELECT * FROM payments WHERE user_id=? ORDER BY created DESC LIMIT 50", (user["id"],))
    return {"payments": [_payment_out(p) for p in rows]}


@app.get("/api/activity")
def activity(sess=Depends(active_session)):
    _, user = sess
    rows = db.q("SELECT ts, type, network, device, detail FROM events WHERE user_id=? ORDER BY ts DESC LIMIT 60",
                (user["id"],))
    return {"events": [{"time": datetime.fromtimestamp(r["ts"], timezone.utc).isoformat(timespec="seconds"),
                        "type": r["type"], "network": r["network"], "device": r["device"],
                        "detail": json.loads(r["detail"] or "{}")} for r in rows]}


# ---------------------------------------------------------------- owner admin
def _admin_ready(session, user) -> bool:
    return is_admin(user) and session["state"] == "active" and \
        {"password", "totp", "passkey"} <= set(json.loads(session["satisfied"]))


def admin_session(request: Request):
    s, user = current_session(request, active=True)
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Admins only")
    if not _admin_ready(s, user):
        raise HTTPException(status_code=403, detail="Admin needs a sign-in with password, authenticator code and passkey")
    return s, user


class AdminSettings(BaseModel):
    maintenance_banner: Optional[str] = Field(None, max_length=300)
    registration_open: Optional[bool] = None
    payments_enabled: Optional[bool] = None
    demo_signals_enabled: Optional[bool] = None


def _count(sql: str, args=()) -> int:
    return db.q1(sql, args)["n"]


@app.get("/api/admin/stats")
def admin_stats(sess=Depends(admin_session)):
    day = time.time() - 86400
    users = _count("SELECT COUNT(*) AS n FROM users")
    totp_users = _count("SELECT COUNT(*) AS n FROM users WHERE totp_secret_enc IS NOT NULL")
    pk_users = _count("SELECT COUNT(DISTINCT user_id) AS n FROM passkeys")
    statuses = {r["status"]: r["n"] for r in db.q("SELECT status, COUNT(*) AS n FROM payments GROUP BY status")}
    events_24h = {r["type"]: r["n"] for r in db.q("SELECT type, COUNT(*) AS n FROM events WHERE ts > ? GROUP BY type "
                                                  "ORDER BY n DESC", (day,))}
    risks = [json.loads(r["risk"])["score"] for r in db.q("SELECT risk FROM payments")]
    bands = {"low": sum(x < 0.25 for x in risks), "medium": sum(0.25 <= x < 0.6 for x in risks),
             "high": sum(x >= 0.6 for x in risks)}
    return {
        "users": {"total": users, "authenticator_app": totp_users, "passkey": pk_users,
                  "all_three_factors": _count("SELECT COUNT(*) AS n FROM users u WHERE totp_secret_enc IS NOT NULL "
                                              "AND EXISTS (SELECT 1 FROM passkeys p WHERE p.user_id=u.id)"),
                  "suspended": _count("SELECT COUNT(*) AS n FROM users WHERE locked_until >= ?", (LOCKED_FOREVER,)),
                  "temporarily_locked": _count("SELECT COUNT(*) AS n FROM users WHERE locked_until > ? AND locked_until < ?",
                                               (time.time(), LOCKED_FOREVER)),
                  "new_24h": _count("SELECT COUNT(*) AS n FROM users WHERE created > ?", (day,))},
        "payments": {"by_status": statuses, "risk_bands": bands,
                     "approved_value": round(db.q1("SELECT COALESCE(SUM(amount),0) AS v FROM payments "
                                                   "WHERE status='approved'")["v"], 2)},
        "events_24h": events_24h,
        "active_sessions": _count("SELECT COUNT(*) AS n FROM sessions WHERE state='active' AND last_seen > ?",
                                  (time.time() - SESSION_IDLE,)),
        "retention_days": db.RETENTION_DAYS,
    }


@app.get("/api/admin/users")
def admin_users(sess=Depends(admin_session)):
    rows = db.q("SELECT u.id, u.email, u.name, u.created, u.locked_until, u.failed_count, "
                "u.totp_secret_enc IS NOT NULL AS totp, "
                "(SELECT COUNT(*) FROM passkeys p WHERE p.user_id=u.id) AS passkeys, "
                "(SELECT COUNT(*) FROM payments p WHERE p.user_id=u.id) AS payments, "
                "(SELECT MAX(ts) FROM events e WHERE e.user_id=u.id AND e.type='login_success') AS last_login "
                "FROM users u ORDER BY u.created DESC LIMIT 500")
    iso = lambda t: datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="seconds") if t else None  # noqa: E731
    return {"users": [{"id": r["id"], "email": r["email"], "name": r["name"], "created": iso(r["created"]),
                       "last_login": iso(r["last_login"]), "authenticator_app": bool(r["totp"]),
                       "passkeys": r["passkeys"], "payments": r["payments"], "admin": r["email"] in ADMIN_EMAILS,
                       "status": "suspended" if r["locked_until"] >= LOCKED_FOREVER else
                                 "locked" if r["locked_until"] > time.time() else "active"} for r in rows]}


def _target(uid: int, admin_user):
    t = db.q1("SELECT * FROM users WHERE id = ?", (uid,))
    if not t:
        raise HTTPException(status_code=404, detail="User not found")
    if t["id"] == admin_user["id"] or t["email"] in ADMIN_EMAILS:
        raise HTTPException(status_code=409, detail="Admin accounts cannot be changed here")
    return t


@app.post("/api/admin/users/{uid}/suspend")
def admin_suspend(uid: int, request: Request, sess=Depends(admin_session)):
    require_json(request)
    t = _target(uid, sess[1])
    db.run("UPDATE users SET locked_until=? WHERE id=?", (LOCKED_FOREVER, uid))
    db.run("DELETE FROM sessions WHERE user_id=?", (uid,))
    db.log_event(sess[1]["id"], "admin_suspended_user", **ctx(request), target=t["email"])
    return {"ok": True}


@app.post("/api/admin/users/{uid}/unlock")
def admin_unlock(uid: int, request: Request, sess=Depends(admin_session)):
    require_json(request)
    t = _target(uid, sess[1])
    db.run("UPDATE users SET locked_until=0, failed_count=0 WHERE id=?", (uid,))
    db.log_event(sess[1]["id"], "admin_unlocked_user", **ctx(request), target=t["email"])
    return {"ok": True}


@app.post("/api/admin/users/{uid}/sign-out")
def admin_sign_out(uid: int, request: Request, sess=Depends(admin_session)):
    require_json(request)
    t = _target(uid, sess[1])
    n = db.run("DELETE FROM sessions WHERE user_id=?", (uid,)).rowcount
    db.log_event(sess[1]["id"], "admin_signed_out_user", **ctx(request), target=t["email"], sessions=n)
    return {"ok": True, "sessions_ended": n}


@app.delete("/api/admin/users/{uid}")
def admin_delete(uid: int, request: Request, sess=Depends(admin_session)):
    t = _target(uid, sess[1])
    db.delete_user(uid)
    db.log_event(sess[1]["id"], "admin_deleted_user", **ctx(request), target=t["email"])
    return {"ok": True}


@app.get("/api/admin/audit")
def admin_audit(type: str = "", email: str = "", limit: int = 200, sess=Depends(admin_session)):
    sql = ("SELECT e.ts, e.type, e.network, e.device, e.detail, u.email FROM events e "
           "LEFT JOIN users u ON u.id = e.user_id WHERE 1=1")
    args: list = []
    if type:
        sql += " AND e.type LIKE ?"
        args.append(f"%{type}%")
    if email:
        sql += " AND u.email = ?"
        args.append(email.strip().lower())
    sql += " ORDER BY e.ts DESC LIMIT ?"
    args.append(min(max(limit, 1), 500))
    return {"events": [{"time": datetime.fromtimestamp(r["ts"], timezone.utc).isoformat(timespec="seconds"),
                        "email": r["email"], "type": r["type"], "network": r["network"], "device": r["device"],
                        "detail": json.loads(r["detail"] or "{}")} for r in db.q(sql, args)]}


@app.get("/api/admin/settings")
def admin_get_settings(sess=Depends(admin_session)):
    return db.get_settings()


@app.put("/api/admin/settings")
def admin_put_settings(body: AdminSettings, request: Request, sess=Depends(admin_session)):
    require_json(request)
    changes = {k: v for k, v in body.model_dump().items() if v is not None}
    out = db.set_settings(changes)
    db.log_event(sess[1]["id"], "admin_changed_settings", **ctx(request), **{k: str(v) for k, v in changes.items()})
    return out


@app.post("/api/admin/clear-demo-data")
def admin_clear(request: Request, confirm: str = "", sess=Depends(admin_session)):
    require_json(request)
    if confirm != "DELETE":
        raise HTTPException(status_code=422, detail="Pass ?confirm=DELETE to remove every non-admin account")
    ids = [r["id"] for r in db.q("SELECT id, email FROM users") if r["email"] not in ADMIN_EMAILS]
    for uid in ids:
        db.delete_user(uid)
        db.run("DELETE FROM events WHERE user_id=?", (uid,))
    db.log_event(sess[1]["id"], "admin_cleared_demo_data", **ctx(request), accounts_removed=len(ids))
    return {"ok": True, "accounts_removed": len(ids)}


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    logging.exception("unhandled error")
    return JSONResponse(status_code=500, content={"detail": "Something went wrong"})

"""Live smoke test for the deployed SecurePay 3FA demo (run by GitHub Actions).

Registers a throwaway demo account, enrols an authenticator app, makes an
exempt payment, a stepped-up payment confirmed with a code, and a simulated
attacker payment that must be blocked. Standard library only.

    python scripts/smoke_test.py https://three-factor-authentication-for-online.onrender.com
"""
import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request


def totp(secret: str, t: float) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", int(t // 30)), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000).zfill(6)


class Client:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, path, body=None, signals="", timeout=90):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, headers={
            "Content-Type": "application/json", "User-Agent": "securepay-smoke-test", "X-Demo-Signals": signals})
        try:
            with self.opener.open(req, timeout=timeout) as r:
                return r.status, json.loads(r.read() or b"{}"), r.headers
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}"), e.headers


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "https://three-factor-authentication-for-online.onrender.com"
    c = Client(base)
    start, last = time.time(), None
    while True:
        try:
            status, health, headers = c.call("/health")
            if status == 200:
                break
        except Exception as e:  # cold start
            last = e
        if time.time() - start > 300:
            raise SystemExit(f"FAIL /health not ok after 300s ({last})")
        time.sleep(10)
    print(f"OK   /health after {time.time() - start:.0f}s")

    problems = []
    status, _, headers = c.call("/")
    csp = headers.get("Content-Security-Policy", "")
    if status != 200 or "default-src 'self'" not in csp or "max-age" not in headers.get("Strict-Transport-Security", ""):
        problems.append("security headers missing on /")

    email = f"smoke-{os.urandom(5).hex()}@example.com"
    status, _, _ = c.call("/api/register", {"name": "Smoke Test", "email": email,
                                            "password": base64.b32encode(os.urandom(10)).decode()})
    if status != 200:
        raise SystemExit(f"FAIL register returned {status}")
    _, s, _ = c.call("/api/totp/setup", {})
    secret = s["secret"]
    status, _, _ = c.call("/api/totp/confirm", {"code": totp(secret, time.time())})
    if status != 200:
        raise SystemExit("FAIL totp confirm")
    print("OK   register + authenticator enrolment")

    _, p, _ = c.call("/api/payments", {"payee": "Corner shop", "amount": 12})
    if p.get("status") != "approved":
        problems.append(f"exempt payment not approved: {p}")
    _, p, _ = c.call("/api/payments", {"payee": "Landlord", "amount": 150})
    if p.get("status") != "step_up" or p.get("required") != ["totp"]:
        problems.append(f"£150 payment should need a code: {p}")
    else:
        time.sleep(31)  # the enrolment code's time step cannot be reused
        _, done, _ = c.call(f"/api/payments/{p['id']}/totp", {"code": totp(secret, time.time())})
        if done.get("status") != "approved":
            problems.append(f"code did not approve payment: {done}")
    _, p, _ = c.call("/api/payments", {"payee": "Unknown exchange", "amount": 150},
                     signals="new_device,new_network,odd_hour,failures")
    if p.get("status") != "blocked":
        problems.append(f"simulated attacker not blocked: {p.get('status')} {p.get('risk')}")
    print(f"OK   payments: exempt, step-up and block checked ({len(problems)} problems)")

    _, ev, _ = c.call("/api/activity")
    blob = json.dumps(ev)
    if secret in blob:
        problems.append("audit log leaked the TOTP secret")
    c.call("/api/logout", {})
    if problems:
        raise SystemExit("FAIL " + "; ".join(problems))
    print("OK   all live checks passed")


if __name__ == "__main__":
    main()

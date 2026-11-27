# Security design and threat model

SecurePay 3FA is a portfolio demo of how a bank-style service can combine three
authentication factors with risk-based step-up. No real money moves. This file
records what it defends against, how, and what it does not cover.

## Assets

User accounts, authentication secrets (password hashes, authenticator seeds,
passkey public keys), sessions, and the authorisation of payments.

## Threats and controls

| Threat | Control |
|---|---|
| Stolen password database | scrypt (N=2^15, r=8, p=3, OWASP setting), random salt per user; hashes upgrade on login when parameters change |
| Credential stuffing / brute force | Rate limits per network and per account; account lock after 5 failures for 15 min; generic error messages; constant work for unknown emails (no account enumeration by timing) |
| Weak passwords | Minimum 10 characters, common-password deny-list, no email name in password (NIST SP 800-63B) |
| Phished or stolen password alone | A second factor is required whenever risk is not low, and for every non-exempt payment |
| Authenticator seed theft from the database | Seeds encrypted at rest (Fernet, key from `ENCRYPTION_KEY`) |
| One-time code replay or guessing | Each code's time step can be used once; ±1 step drift only; 5 wrong codes cancel the attempt |
| Real-time phishing of codes (adversary-in-the-middle) | High-value and high-risk payments need a passkey: WebAuthn signatures are bound to this site's origin, so a phishing site cannot obtain a usable signature |
| Authorising a different payment than the user saw | The passkey challenge is SHA-256 over payment id, amount, currency and payee plus a nonce (PSD2 "dynamic linking"), and each payment's challenge is single-use |
| Passkey without the person present | User verification is **required** (fingerprint, face or device PIN), not just presence |
| Cloned authenticator | Signature counter checked by the WebAuthn library and updated after every use |
| Session theft | Random 256-bit tokens stored only as SHA-256 hashes; HttpOnly, Secure, SameSite=Strict cookies; 30-minute idle expiry |
| Cross-site request forgery | SameSite=Strict cookies and JSON-only state-changing endpoints |
| Cross-site scripting / clickjacking | Strict Content-Security-Policy (no inline script or style), output escaping in the UI, `frame-ancestors 'none'`, X-Frame-Options DENY |
| Leaking secrets in logs | Audit trail records event type, coarse network (/24 or /48), short device tag and amounts only: never passwords, codes, seeds or full IPs |
| Vulnerable dependencies | pip-audit in CI, Dependabot weekly, CodeQL and Bandit static analysis |

## Known limits (demo scope)

- **Storage is ephemeral.** SQLite on the free host's disk; data resets on
  restart and accounts are deleted after 3 days. Without `ENCRYPTION_KEY` the
  app uses a per-process key.
- **The risk model is trained on simulated behaviour** (see
  `docs/risk_model.md`); production needs real labelled fraud data.
- **No account recovery flow.** Recovering a lost second factor safely (recovery
  codes, identity verification) is out of scope.
- **Rate limits are per instance**, kept in the database; a multi-instance
  deployment would use a shared store such as Redis.
- **Network identity uses `X-Forwarded-For`** from the hosting proxy; behind an
  untrusted proxy this must be restricted to trusted hops.

## Reporting

Please open a GitHub issue (without sensitive details) or contact the author via
LinkedIn.

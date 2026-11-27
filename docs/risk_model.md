# Risk model

The risk engine decides how many factors a login or a payment needs. It is a
logistic regression over a handful of behavioural signals, chosen because it is
fast, needs no ML library at runtime (the app evaluates stored coefficients),
and every score can be explained signal by signal.

## Signals

| Signal | Login | Payment | How it is computed |
|---|---|---|---|
| `new_device` | ✓ | ✓ | Device cookie not seen before for this user |
| `new_network` | ✓ | ✓ | IPv4 /24 or IPv6 /48 not seen before (full IP is never stored) |
| `odd_hour` | ✓ | ✓ | Circular distance from the user's usual sign-in hour (0 = usual, 1 = 12 h away; needs 3+ past sign-ins) |
| `recent_failures` | ✓ | ✓ | Failed password, code or passkey attempts in the last hour (capped at 5) |
| `amount_ratio` | | ✓ | log10(amount / median of the user's past payments, floor 20) |
| `new_payee` | | ✓ | No approved payment to this payee before |
| `velocity` | | ✓ | Payments started in the last hour (capped at 5) |

## Training data: simulated, and why

There is no public, licensed dataset of labelled account-takeover attempts
carrying these signals. `scripts/train_risk_model.py` therefore **simulates**
60,000 sessions (3% account takeover, seed 42): genuine users mostly appear on
known devices and networks at their usual hours, paying known payees typical
amounts; attackers mostly do not. The distributions overlap on purpose
(travel, new phones, first-time payees, careful attackers).

Held-out results on the simulated data:

| Model | ROC-AUC | PR-AUC | At risk ≥ 0.25: takeovers challenged | genuine users challenged |
|---|---|---|---|---|
| Login | 0.977 | 0.806 | 72% | 0.9% |
| Payment | 0.995 | 0.942 | 90% | 0.5% |

These numbers show the method works on data that behaves as assumed; **they
are not evidence about real fraud.** A production system would retrain on
labelled fraud, chargeback and customer-confirmed incidents, monitor drift,
and tune thresholds to the business cost of false declines versus losses.
CI retrains the model on every push and fails if the simulation's AUC drops
below 0.95 (payment) or 0.90 (login), which catches accidental changes to the
features or training code.

## How scores are used

See `app/policy.py`. Low-value, low-risk payments (≤ 30, under 100 or 5
payments since the last full authentication) are exempt, as in PSD2 RTS
Article 16. Otherwise a code is required; a passkey is also required when the
amount is ≥ 500 or risk ≥ 0.6; risk ≥ 0.9 blocks the payment for review.

The demo's "Simulate risk signals" panel overrides signals for that request
only (and is recorded as simulated in the audit log), so visitors can see
step-up without being attackers. Set `DEMO_MODE=false` to disable it.

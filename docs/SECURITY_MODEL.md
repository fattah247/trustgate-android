# Security Model

## Risk signals

The app collects a small set of root, emulator, debugger, and installer-source signals. Each signal has an id, severity, detection flag, and short explanation.

## Risk scoring

Detected signals contribute to a simple score:

- Low score with no serious findings maps to `LOW`
- A moderate score or multiple weaker findings maps to `MEDIUM`
- A severe signal or high total score maps to `HIGH`

This scoring is intentionally readable. It is not a hidden fraud model. Each report carries the rule that produced its level, so the app can explain a verdict rather than only show it. Simulated profiles go through the same scorer, so a profile can't claim a level its own signals don't produce.

## Sensitive action gate

The payment-like action follows one rule set:

- `LOW`: allow
- `MEDIUM`: require confirmation
- `HIGH`: block

With live checks, the device is assessed again each time the action runs, so a debugger or root tool attached after launch still changes the decision. Returning to the app also re-checks a verdict older than 30 seconds; that quiet check is logged only when the level or the set of detected signals changed.

Confirmation for `MEDIUM` uses the system biometric prompt with biometrics or the screen lock. Without a screen lock there is nothing to step up to, so the app falls back to an explicit tap and records the method used.

When the gate allows the action, the app signs the reference payment request and submits it to the reference verifier. A blocked or cancelled action signs nothing. Simulated `LOW`, `MEDIUM`, and `HIGH` profiles replace live checks everywhere in the app until you switch back to live.

Every decision becomes a local security event, including a confirmation that the user cancels.

## Event logging

The app keeps a local event log so the user can see why an action was allowed, escalated, cancelled, blocked, signed, or stored. It keeps the latest 150 events, and the user can clear it from the Activity tab after confirming.

## Secure storage

The app stores:

- A reference session token
- The last assessed risk level
- A harmless UI preference

These values live in encrypted shared preferences through Jetpack Security.

## Request signing and verification

The request-signing workflow builds a canonical request body, hashes that body, and signs the method, path, timestamp, nonce, and body hash with HMAC-SHA256. Signer and verifier share one definition of that scheme.

The reference verifier stands in for the server. In order, it requires the signing headers, parses the timestamp, rejects anything more than five minutes from its arrival time in either direction, recomputes the signature and compares it in constant time, and only then claims the nonce. Claiming last means a forged request can't use up a genuine request's nonce. Nonces are remembered for twice the window, after which a replay would fail the time check anyway.

This shows the shape of a signed request and of server-side checks, but it does not claim safe production key management.

## Certificate pinning

The repo includes a disabled-by-default OkHttp certificate pinning example. It is present to discuss pinning tradeoffs, not to force a fragile network setup into the reference build.

## Layered defense, not absolute security

TrustGate Android uses layers: risk signals, user confirmation, local encryption, request-signing shape, and audit-style events. None of those layers are enough on their own, and none of them make the client authoritative.

# Security Model

## Risk signals

The app collects a small set of root, emulator, debugger, and installer-source signals. Each signal has an id, severity, detection flag, and short explanation.

## Risk scoring

Detected signals contribute to a simple score:

- Low score with no serious findings maps to `LOW`
- A moderate score or multiple weaker findings maps to `MEDIUM`
- A severe signal or high total score maps to `HIGH`

This scoring is intentionally readable. It is not a hidden fraud model.

## Sensitive action gate

The payment-like action follows one rule set:

- `LOW`: allow
- `MEDIUM`: require confirmation
- `HIGH`: block

Every decision becomes a local security event.

## Event logging

The app keeps a local event log so the user can see why an action was allowed, escalated, blocked, signed, or stored.

## Secure storage

The app stores:

- A mock session token
- The last assessed risk level
- A harmless UI preference

These values live in encrypted shared preferences through Jetpack Security.

## Request signing

The signing demo builds a canonical request body, hashes that body, and signs request inputs with HMAC-SHA256. This shows the shape of a signed request but does not claim safe production key management.

## Certificate pinning

The repo includes a disabled-by-default OkHttp certificate pinning example. It is present to discuss pinning tradeoffs, not to force a fragile network setup into the demo.

## Layered defense, not absolute security

TrustGate Android uses layers: risk signals, user confirmation, local encryption, request-signing shape, and audit-style events. None of those layers are enough on their own, and none of them make the client authoritative.


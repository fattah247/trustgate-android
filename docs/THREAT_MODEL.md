# Threat Model

## What the app protects

TrustGate Android protects a payment-like action from being treated the same on every device state. The app also protects a few mock local values from plain-text storage.

## Attacker assumptions

- The attacker may run the app on a rooted device.
- The attacker may use an emulator for testing or tampering.
- The attacker may attach a debugger to inspect runtime behavior.
- The attacker may replay a request shape if the client never uses nonce and timestamp inputs.

## Threats modeled

- Rooted-device signals such as `su` paths, root packages, and test-keys builds
- Emulator signals from device build strings
- Debugger-attached and debuggable-build signals
- Sensitive action attempts on a high-risk device
- Replay-shaped request risk through nonce and timestamp signing inputs
- Unsafe local storage for session-like values

## Threats not modeled

- Advanced bypass frameworks
- Kernel-level compromise
- Real fraud detection
- Real payment processor compromise
- Production key management
- Server-side attestation verification

## Trust boundaries

- Device runtime: low trust, because the user can modify it
- App process: medium trust, useful for collecting signals but not an authority
- Local encrypted storage: safer than plain preferences, still on the device
- Backend boundary: simulated only; there is no live server in this repo

## Why client-side checks are only signals

The app can inspect its own environment, but it cannot prove that the environment is honest. A determined attacker can hide or bypass many checks. That is why TrustGate Android uses risk levels and layered controls instead of claiming absolute enforcement.


# Threat Model

## What the app protects

TrustGate Android protects a payment-like action from being treated the same on every device state, makes sure only this device can sign its requests, and keeps a retried payment from being charged twice. It also protects a few reference local values from plain-text storage.

## Attacker assumptions

- The attacker may run the app on a rooted device.
- The attacker may use an emulator for testing or tampering.
- The attacker may attach a debugger or a hooking framework to inspect and change runtime behavior.
- The attacker may capture, replay, edit, or delay requests in transit.
- The attacker may decompile the app.
- The network may drop responses, so the client can't always tell whether a payment went through.

## Threats modeled

- Rooted-device signals such as `su` paths, root packages, and test-keys builds
- Emulator signals from device build strings
- Debugger-attached and debuggable-build signals
- Sensitive action attempts on a high-risk device, refused by the backend before any challenge is issued
- A device that turns high risk while the person is confirming, caught by a second check before signing
- Faked confirmation: hooking the biometric prompt's success callback yields no step-up signature, because the step-up key only signs after real authentication
- A step-up key that doesn't actually require authentication, refused when its attestation says so
- A step-up key slipped in from elsewhere, or a step-up key removed to downgrade the device to a tap, both refused unless the device key signs the change
- Attestation chains that can't be read or that certify another key, refused at registration
- Key extraction from the APK: there is no shared secret to extract; private keys stay in Keystore
- Replayed, edited, and held-back requests, refused through one-time challenges, signature checks, and the timestamp window
- Double charging after a lost response or a captured request, prevented by idempotency keys
- Sensitive values in backups, screenshots, screen recordings, or the recents view
- Tapjacking through overlay windows on sensitive screens

## Threats not modeled

- Advanced hooking frameworks that also defeat the backend's view of the device, which needs a Play Integrity verdict to address
- Kernel-level compromise
- Real fraud detection
- Real payment processor compromise
- A compromised server, or key revocation and rotation

## Trust boundaries

- Device runtime: low trust, because the person or an attacker can modify it
- App process: medium trust, useful for collecting signals but not an authority
- Android Keystore: higher trust; private keys can be used but not read, and in secure hardware they're out of reach of the app process
- Backend boundary: simulated by an in-process reference backend that verifies with registered public keys; there is no live server in this repo

## Why client-side checks are only signals

The app can inspect its own environment, but it cannot prove that the environment is honest. A determined attacker can hide or bypass many checks. That is why TrustGate Android treats them as evidence for a server-side decision, binds sensitive operations to keys the device can't export, and claims no absolute enforcement.

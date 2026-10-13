# Limitations

- TrustGate Android does not claim bypass-proof client security.
- The app does not connect to a real payment processor or bank system.
- Device checks are heuristic signals and can be hidden or bypassed by a determined attacker. A production backend would rely on a Play Integrity verdict instead, which this repo doesn't have.
- The reference backend runs inside the app process. It verifies with registered public keys, but it isn't an independent authority, and its registered keys, challenges, and payment ledger last only as long as the process. The app registers fresh keys each launch for that reason.
- Attestation chains are checked for internal consistency, the registered key, and the issued challenge, but not against Google's attestation roots or revocation list.
- Emulators and many test devices attest keys in software, which the app reports as such.
- Step-up confirmation falls back to a signed tap on devices without a screen lock; that path is weaker by design and is labelled as such in the log.
- Certificate pinning is implemented as an example and would need backup pins and rotation planning in a real deployment.
- Screen capture is only blocked in release builds, so debug builds can be documented and tested.
- The event log is local to the device. It is useful for explanation, not for tamper-proof forensics.

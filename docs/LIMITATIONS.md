# Limitations

- TrustGate Android does not claim bypass-proof client security.
- The app does not connect to a real payment processor or bank system.
- Device checks are heuristic signals and can be hidden or bypassed by a determined attacker.
- Request signing uses a reference local key and does not represent production key custody.
- The reference verifier runs on the device with the same key, so it demonstrates server-side checks without being an independent authority. Its nonce memory lasts only while the app process lives.
- Step-up confirmation falls back to a tap on devices without a screen lock; that path is weaker by design and is labelled as such in the log.
- There is no live Play Integrity or server attestation validation flow in this repo.
- Certificate pinning is implemented as an example and would need rotation planning in a real deployment.
- The event log is local to the device. It is useful for explanation, not for tamper-proof forensics.

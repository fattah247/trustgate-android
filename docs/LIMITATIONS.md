# Limitations

- TrustGate Android does not claim bypass-proof client security.
- The app does not connect to a real payment processor or bank system.
- Device checks are heuristic signals and can be hidden or bypassed by a determined attacker.
- Request signing uses a demo-only local key and does not represent production key custody.
- There is no live Play Integrity or server attestation validation flow in this repo.
- Certificate pinning is implemented as an example and would need rotation planning in a real deployment.
- The event log is local to the device. It is useful for explanation, not for tamper-proof forensics.


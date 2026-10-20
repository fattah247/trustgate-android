# Limitations

- **On-phone checks can be made to lie.** Root, emulator, debugger, call, and screen checks run inside an app on a phone the attacker may control. They're evidence for the server, not proof. What such a phone can't forge is its hardware attestation and the Play Integrity verdict, which only the strict policy requires.
- **The development policy is deliberately weak.** It accepts software and unattested keys, made-up Play Integrity answers, and demo phones, so the whole flow runs on an emulator. `./gradlew :server:run` uses it unless `-Ptrustgate.policy=strict` is given; the server binary on its own defaults to strict.
- **Play Integrity needs a Play Console app.** Real verdicts need the app published to a Play track, a linked Google Cloud project (`trustgate.cloudProjectNumber`), the optional verdicts turned on in Play Console, and a service account for the server. Without them, debug builds send made-up answers that only the development policy accepts.
- **Play's own fix-it dialogs are only offered for real verdicts.** With made-up answers the app explains the fix in words instead.
- **Accessibility-sensitive views aren't used.** Android 14 can hide marked views from accessibility services that aren't accessibility tools, but Compose doesn't yet pass that mark through to its own nodes in a way this app can rely on, so it counts on the app-access verdict and its own accessibility check instead.
- **Screen recording is only detected on Android 15 and later**, and only for the app's own window.
- **No accounts.** A phone is its key. The new-phone rules, limits, and revocation work per phone; a person with several phones, or one who keeps starting over, is a matter for account-level fraud checks.
- **Limits are per phone and in one currency.** The daily cap adds amounts without converting currencies; the reference payment is always in IDR.
- **The audit chain shows edits; it doesn't prevent them.** Someone who can rewrite the whole table and recompute every hash would only be caught by comparing against a head hash kept elsewhere, such as the one the server logs at startup.
- **The step-up key falls back to a signed tap** on phones without a screen lock. That path is weaker by design, and the log says which was used.
- **A device that can't attest keys at all** can't register a step-up key, because Keystore can't sign that key's own certificate without authentication. Medium risk then falls back to the tap.
- **No payment processor.** Payments are recorded in the server's ledger and nothing else.
- **Screen capture is only blocked in release builds**, so debug builds can be documented and tested.
- **The app's activity log is local** and editable by anyone who controls the phone. The server's audit log is the record that counts.
- **R8 is the only obfuscation.** There's no string encryption or code virtualisation; the design keeps no secret in the app to protect.

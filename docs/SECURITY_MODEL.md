# Security Model

## Risk signals

The app collects a small set of root, emulator, debugger, and installer-source signals. Each signal has an id, severity, detection flag, and short explanation.

## Risk scoring

Detected signals contribute to a simple score:

- Low score with no serious findings maps to `LOW`
- A moderate score or multiple weaker findings maps to `MEDIUM`
- A severe signal or high total score maps to `HIGH`

This scoring is intentionally readable. It is not a hidden fraud model. Each report carries the rule that produced its level, so the app can explain a verdict rather than only show it. Simulated profiles go through the same scorer, so a profile can't claim a level its own signals don't produce.

## Device keys

At launch the app generates two P-256 key pairs in Android Keystore, in StrongBox when the device has it:

- The **device key** signs ordinary requests.
- The **step-up key** can only sign right after the person authenticates with strong biometrics or their screen lock. Each signature needs a fresh authentication, and adding a fingerprint or removing the lock destroys the key. On Android 10 and lower the key is bound to biometrics only. Devices without a screen lock don't get a step-up key.

Each key is generated with a one-time attestation challenge from the backend. The backend registers the key from its attestation certificate chain and checks that:

- each certificate is signed by the next, and the last signs itself,
- the first certificate certifies the very key being registered,
- the attestation carries the challenge the backend issued,
- for a step-up key, the attestation shows the key requires user authentication.

A key presented without a chain, or with one that can't be read or fails any of these checks, is refused. A device that can't attest at all returns only the key's own self-signed certificate; that key is registered and reported as unattested. The backend records where each key lives, the verified boot state, and whether the bootloader is locked. A production backend would also pin Google's attestation roots and check the revocation list.

The step-up key is tied to its device key. Registering one needs the device key's signature over the registration challenge and the new key's ID. When the device key is attested, the step-up key must be attested by the same root. Removing a step-up key, for example after the screen lock is turned off, also needs a device-key signature. Without that, anyone who knew a device's key ID could quietly downgrade it from step-up to a tap. The app checks that both keys still exist in Keystore before each payment and registers replacements when the system has deleted them.

## Sensitive action gate

The reference backend, not the app, decides from the device's risk evidence:

- `LOW`: allow; the request must be signed by the device key
- `MEDIUM`: require confirmation; the request must be signed by the step-up key, or carry a signed tap confirmation when the device has no step-up key
- `HIGH`: block; no challenge is issued, so nothing can be signed

With live checks, the device is assessed again each time the action runs and again after a confirmation, so a debugger or root tool attached in between still blocks the action. Returning to the app also re-checks a verdict older than 30 seconds; that quiet check is logged only when the level or the set of detected signals changed.

Confirmation unlocks the step-up key through `BiometricPrompt` with a `CryptoObject`. The person's authentication is what makes the signature possible, so hooking the prompt's success callback gets an attacker nothing the backend will accept.

Simulated `LOW`, `MEDIUM`, and `HIGH` profiles replace live checks everywhere in the app until you switch back to live. Every decision becomes a local security event, including a confirmation the person cancels.

## Request signing and verification

A signed request covers the method, path, timestamp, nonce, key ID, idempotency key, confirmation, and the SHA-256 hash of the canonical body, joined one per line. Header values containing a line break are refused so they can't shift the signed fields. The app and the backend share one definition of this scheme.

The backend checks, in order: the signing headers, the timestamp format, a five-minute window around its arrival time, that the key is registered, and the ECDSA signature. Only then does it look at the nonce, which must be a one-time challenge it issued to this device for this purpose and hasn't expired. A challenge issued for a payment can't be spent on a verification, or the other way around. Checking the challenge last means a forged request can't use up a genuine request's challenge. For payments, an unreadable body or a zero amount is refused before the challenge is spent too.

## Payments and retries

Every payment carries an idempotency key, scoped to the device that sent it. The backend charges at most once per key:

- The same signed request sent again, for example after a timeout, gets the original payment back, even though its challenge was already spent.
- The same key with a different body is refused as an idempotency conflict.

The client resends the identical request after a lost response, up to three attempts, with exponential backoff and jitter. If every response is lost it reports the outcome as unknown, and a later retry with the same key is still safe. Once a payment is sent, the app finishes its retries and logs the outcome even if the person leaves the screen, so a charge never goes unrecorded. The Sensitive action screen has a switch that loses the first response on purpose to show this.

## Secure storage

The app stores a reference session token, the last assessed risk level, and a display preference. Each value is encrypted with AES-256-GCM under a key held in Android Keystore, with the value's name as associated data, so a ciphertext copied into another slot fails to decrypt. A value that fails authentication, for example after a restore onto another device, is removed and reported rather than shown wrong. Other Keystore errors may be temporary, so they are reported and the value is kept.

This replaces Jetpack Security's `EncryptedSharedPreferences`, which Google deprecated. Values that library wrote are migrated on first run. Its file is deleted once the migrated values are saved, or straight away if the old library can't read it.

## Platform hardening

- Backups are off, and data extraction rules keep stored values and the audit log out of cloud backup and device-to-device transfer, since their keys can't follow them.
- Sensitive screens, and the tap confirmation dialog, ignore touches that arrive through another app's overlay. In release builds they also set `FLAG_SECURE`, which blocks screenshots, screen recording, and the recents thumbnail. Debug builds allow capture for documentation and tests.
- Release builds are shrunk and obfuscated with R8. That raises the cost of reverse engineering; it doesn't prevent it.

## Event logging

The app keeps a local event log so the person can see why an action was allowed, escalated, cancelled, blocked, signed, or charged, and which keys were registered. It keeps the latest 150 events, can be cleared after a confirmation, and can be shared as a JSON file.

## Certificate pinning

The repo includes a disabled-by-default OkHttp certificate pinning example. It is present to discuss pinning tradeoffs, not to force a fragile network setup into the reference build.

## Layered defense, not absolute security

TrustGate Android uses layers: risk signals, a server-side decision, hardware-backed keys, cryptographic step-up, replay protection, idempotent payments, local encryption, and audit events. None of them is enough on its own, and none of them makes the client authoritative.

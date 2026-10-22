# OWASP MASVS Mapping

How TrustGate lines up with the [OWASP Mobile Application Security Verification Standard](https://mas.owasp.org/MASVS/) v2 controls. **Met** means the control is implemented and tested here. **Partly** means some of it is, and the gap is named. **Out of scope** means the app has nothing the control applies to.

This is a self-assessment against the control statements, not a MASTG test run or a certification.

## MASVS-STORAGE

| Control | Status | How |
| --- | --- | --- |
| STORAGE-1: stores sensitive data securely | Met | Values are sealed with AES-256-GCM under a Keystore key, with each value's name as associated data so a ciphertext moved to another slot won't open (`core/storage`). Private keys never leave Keystore. |
| STORAGE-2: prevents leakage of sensitive data | Met | Backups are off and the data extraction rules exclude stored values and the log. Release builds set `FLAG_SECURE` on sensitive screens. Logs carry no secrets: the server logs method, path, and status only. |

## MASVS-CRYPTO

| Control | Status | How |
| --- | --- | --- |
| CRYPTO-1: current, strong cryptography | Met | ECDSA P-256 with SHA-256 for every signature, AES-256-GCM for storage, SHA-256 for body hashes, request hashes, and the audit chain. No custom algorithms. |
| CRYPTO-2: key management | Met | Keys are generated inside Keystore (StrongBox when present), attested to the server, never exported, replaced by rotation the old key vouches for, and revoked for good on rotation, removal, or an operator's decision. The step-up key needs a fresh authentication for each signature and is destroyed when the fingerprints or the screen lock change. |

## MASVS-AUTH

| Control | Status | How |
| --- | --- | --- |
| AUTH-1: secure authentication and authorization | Partly | Every request is signed by a registered, attested key and bound to a one-time server challenge, a five-minute window, and an idempotency key; a payment's challenge is bound to the payment itself. Phones belong to accounts, and a new phone gets in only with a one-time code and approval signed by a phone already on the account. Nothing binds an account to a person: login and recovery are left to the host app. |
| AUTH-2: local authentication done the platform's way | Met | Confirmation goes through `BiometricPrompt` with a `CryptoObject`, so authentication unlocks a key the server checks rather than a callback the app trusts. |
| AUTH-3: extra authentication for sensitive operations | Met | The server asks for step-up confirmation on medium risk, for new phones, for payments unlike the account's habits, for phones set up again, and when Play Integrity is only basic; the payment must then be signed by the step-up key. Approving or removing a phone on the account takes the step-up key too, when the phone has one. |

## MASVS-NETWORK

| Control | Status | How |
| --- | --- | --- |
| NETWORK-1: secures all network traffic | Met | The server listens on HTTPS only. The app's network security config, generated per build, disallows cleartext. |
| NETWORK-2: identity pinning for endpoints under the developer's control | Met | Debug builds trust only the development server's own certificate and pin its key. Release builds pin the keys given as Gradle properties. |

## MASVS-PLATFORM

| Control | Status | How |
| --- | --- | --- |
| PLATFORM-1: secure IPC | Met | One exported component, the launcher activity. The audit export goes through a `FileProvider` that isn't exported and grants one URI at a time. |
| PLATFORM-2: secure WebViews | Out of scope | The app has no WebView. |
| PLATFORM-3: secure user interface | Met | Payment screens hide other apps' overlays (Android 12+), ignore taps that arrive through an overlay, and block capture in release builds. The confirmation dialog filters obscured touches in its own window. The app flags an accessibility service that isn't an accessibility tool, and recording of its own window (Android 15+). |

## MASVS-CODE

| Control | Status | How |
| --- | --- | --- |
| CODE-1: requires an up-to-date platform | Partly | `minSdk` is 26 and `targetSdk` 35. The strict policy can refuse phones below a security patch level, and requires Play's strong integrity, which on Android 13+ includes a recent patch, or a confirmation. |
| CODE-2: enforces app updates | Met | The strict policy refuses app versions below a configured minimum, both when they register a key (from the attestation) and when they pay (from the Play Integrity verdict), and the app sends the person to Google Play. |
| CODE-3: no components with known vulnerabilities | Met | Dependabot for Gradle and Actions, dependency review on pull requests, the dependency graph submitted to GitHub, and Gradle dependency verification against recorded SHA-256 checksums. See [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md). |
| CODE-4: validates untrusted input | Met | The server reads payment bodies strictly, caps signed bodies at 16 KB, refuses header values that could shift signed fields, and parses attestation DER defensively. Jazzer fuzzes the hand-written parsers for attestation chains, the revocation list, and integrity tokens nightly in CI, and each input that broke one is kept as a regression test. CodeQL's extended security queries run on every pull request. |

## MASVS-RESILIENCE

| Control | Status | How |
| --- | --- | --- |
| RESILIENCE-1: validates platform integrity | Met | Hardware key attestation against Google's pinned roots and revocation list (verified boot, locked bootloader, patch level), and Play Integrity's device verdict, both checked on the server. On-phone checks for root, emulators, and debugging feed in as signals. |
| RESILIENCE-2: anti-tampering | Met | The attestation names the app's package and signing certificate, and Play Integrity names the app's certificate and whether Google Play recognises the build; a repackaged app fails both on the server. |
| RESILIENCE-3: anti-static analysis | Partly | R8 shrinks and obfuscates release builds. There's no string encryption or code virtualisation; the design doesn't depend on hiding anything, since no secret ships in the app. |
| RESILIENCE-4: anti-dynamic analysis | Partly | A debugger or debuggable build is reported to the server and scored. Instrumentation on a phone the attacker controls is out of reach of any on-phone check; the server-side attestation and Play Integrity verdicts are what such a phone can't fake. |

## MASVS-PRIVACY

| Control | Status | How |
| --- | --- | --- |
| PRIVACY-1: minimises access to sensitive data | Met | No location, contacts, phone-state, or storage permissions. The call check reads the audio mode, which needs no permission. Package visibility is limited to the root managers the check names. |
| PRIVACY-2: prevents identification of the user | Met | No advertising IDs, analytics, or account data. The server knows a phone by a key ID derived from a public key. |
| PRIVACY-3: transparent about data collection | Met | The Checks tab lists every signal and what each means, and every payment shows what the server saw. |
| PRIVACY-4: user control over their data | Met | The activity log stays on the phone, can be exported or cleared, and the phone can ask the server to forget its keys. |

# Security Model

TrustGate splits the work the way a payment app should: the phone collects evidence and holds keys, and the server decides. Everything below is enforced by the server unless it says otherwise.

## Policies

The server enforces one of two policies, chosen together for keys and devices so it can't be strict about one and lax about the other.

| | Strict (the server's default) | Development (`./gradlew :server:run`) |
| --- | --- | --- |
| Attestation roots | Google's, pinned | Any |
| Revocation list | Required, refreshed every 6 hours | Checked when available |
| Keys | Hardware-backed, generated in Keystore, attested | Software and unattested keys allowed |
| Boot | Verified, bootloader locked | Not required |
| Play Integrity | Required; strong integrity or a confirmation | Made-up answers accepted, and labelled |
| Demo phones | Refused | Accepted, and labelled |
| Payment limits, per account | 5 per 10 minutes, IDR 10,000,000 a day, new phones confirm and stay under IDR 1,000,000 for a day | 3 a minute, same daily cap, no new-phone rules |
| Habit checks | On | On |
| Key age | Replaced after 90 days | No limit |
| Minimum patch level, app version | Configurable | Off |

## Device evidence

Before a payment the app checks the phone and signs what it found with its device key, together with the payment it's for (payee, amount, currency, reference) and the phone's UTC offset:

| Signal | Severity |
| --- | --- |
| Root binary on the path, root manager installed | High |
| Test build of Android, system files writable | Medium |
| Emulator | Medium |
| Debugger attached | High |
| Debug build of the app | Medium |
| Not installed from an app store | Low |
| On a call | Medium |
| Accessibility service that isn't an accessibility tool | Medium |
| The app's window being recorded or shared (Android 15+) | Medium |

Only signal IDs and whether each was found travel to the server. The server scores them from its own catalog, so a tampered app can't lower a severity, and ignores IDs it doesn't know: low adds 1 point, medium 2, high 3. Two points or more asks for confirmation; five or more, or any high signal, blocks. The last three signals also mark the payment as a likely scam.

The evidence carries the time it was collected. The server refuses evidence signed by any key but the phone's, unreadable evidence, and evidence outside the five-minute window.

## Play Integrity

The app requests a Standard Play Integrity token with the SHA-256 of the exact evidence it signed as the request hash, and sends both. The server has Google decode the token with a service account and refuses the verdict unless it was issued for this evidence, this package, within the time window, for a build Google Play recognises, signed with the app's certificate, on a phone that meets device integrity. It then reads the optional verdicts, when they're turned on in Play Console:

| Verdict | Outcome | What the person is told |
| --- | --- | --- |
| An unknown app can capture or control the screen | Block, scam warning | Close apps you don't recognise (Play's dialog) |
| A remote-control app from Google Play is running | Block, scam warning | Close apps that can see or control the screen (Play's dialog) |
| A screen recorder, or an unknown app drawing over the screen | Confirm, scam warning | Close them (Play's dialog) |
| Play Protect found dangerous apps | Block | Open Play Protect and remove them |
| Play Protect found harmful apps, or is turned off | Confirm | Turn on Play Protect |
| The copy wasn't installed from Google Play | Confirm | Install it from Google Play (Play's dialog) |
| Unusually many integrity requests from the phone | Confirm | |
| Only basic integrity, under the strict policy | Confirm | |
| App version below the minimum | Block | Update from Google Play |
| Device recall: this phone was blocked before | Block | |
| Device recall: set up here before, on a key registered in the last day | Confirm | |

Only a fix for the worst problem is offered, and none when something else blocks the payment anyway.

**Device recall** (beta) keeps three bits per phone on Google's side, and they survive a factory reset. The server uses two: the first time Google vouches for a phone, it sets *set up here*; when an operator revokes a phone, it sets *blocked*, using the phone's last Google-verified token if that's under 14 days old. Writes go out in the background once the change that called for them is committed, and marking a phone blocked is recorded in the audit log. So a phone that was blocked stays blocked after a wipe, and one that comes back as "new" says it isn't. Writing needs `TRUSTGATE_DEVICE_RECALL=on`, the Play Integrity credentials, and device recall turned on in Play Console.

## Keys

Each phone has two P-256 keys in Android Keystore, in StrongBox when there is one:

- The **device key** signs device evidence and ordinary payments.
- The **step-up key** signs only right after the person authenticates with strong biometrics or the screen lock, once per authentication. Adding a fingerprint or removing the lock destroys it. Phones without a screen lock don't get one.

Each key is generated with a one-time challenge from the server, which registers it from its attestation certificate chain. The chain must verify up to a trusted root, certify this exact key, carry the challenge, and name the app's package and signing certificate. The strict policy also checks Google's revocation list and requires the key to be generated (not imported) in secure hardware on a verified, locked phone. A step-up key must be vouched for by the device key, attested by the same root, and need authentication for every use.

**Lifecycle.**

- *Rotation:* the device key vouches for its successor, which must be attested at least as well. The phone keeps its identity, enrolment date, and payment history; the old key and its step-up key are revoked.
- *Removal:* the phone can ask the server to forget it, and an operator can revoke a phone by either of its keys.
- *Recovery:* a revoked or unknown key is refused everywhere, and the app sets the phone up again as a new phone.

The app remembers which keys are registered, so it keeps one identity across launches.

## Accounts

Every phone belongs to an account; a phone that registers starts on one of its own. A phone joins another account only with approval from a phone already on it:

1. A phone on the account makes a **link code**: 8 characters from an alphabet without look-alikes, valid for 10 minutes and for one join. A phone that is itself new on the account can't make one.
2. The new phone sends the code, signed with its device key over a fresh challenge. It now waits; it can't pay from the account.
3. A phone on the account **approves** or **declines** it. The decision is signed over a one-time challenge bound to the action and the phone it's about, with the deciding phone's step-up key, so it takes biometrics or the screen lock. A phone without a step-up key confirms with a signed tap.

The same signed decision **removes** a lost phone, which revokes its keys. A phone that's waiting, new, or on another account can't decide anything. A phone that joins counts as new from the moment it joins, so it confirms every payment and stays under the new-phone cap for a day, and every phone on an account shares the account's limits.

## The gate

From the evidence, the verdict, and the phone's history, the server decides:

- **Allow:** the payment is signed by the device key.
- **Confirm:** the payment must be signed by the step-up key, unlocked through `BiometricPrompt` with a `CryptoObject`. Faking the prompt's callback produces no signature. A phone without a screen lock confirms with a tap that's signed into the request, a weaker path the log names.
- **Block:** no challenge is issued, so nothing can be signed.

Every answer carries the server's reasons, each with its own severity, so the app can show what the server saw. The app checks the phone again after a confirmation and stops if it has turned high risk.

## Requests

A signed request covers the method, path, timestamp, nonce, key ID, idempotency key, confirmation, and the SHA-256 of the canonical body, one per line; header values with line breaks are refused. The server checks, in order: the headers, the timestamp format and a five-minute window, that the key is registered and not revoked, and the ECDSA signature. Only then does it look at the nonce, which must be a live challenge it issued to this phone for this purpose. Checking the challenge last means a forged request can't use up a genuine one. Signed bodies over 16 KB, unreadable payment bodies, and zero amounts are refused.

## Payments

- **Bound to what was approved.** The challenge issued for a payment is bound to the SHA-256 of the payment the server weighed. The payment later signed with it must be exactly that one; a different payee, amount, currency, or reference is refused as `payment_changed`.
- **Idempotency.** Every payment carries an idempotency key scoped to the phone. The same signed request sent again gets the original payment back without a second charge; the same key with a different body is refused. The app resends the identical request after a lost response, up to three attempts with exponential backoff and jitter, and finishes and logs a payment even if the person leaves the screen.
- **Habits.** The server compares each payment with the account's last 90 days in the same currency and asks for confirmation when it's the first payment to a payee; when it's more than twice the largest payment, once there are 3 to compare with; or when it's at night (midnight to 5 a.m. in the phone's time zone) for an account with fewer than 3 night payments. The phone reports its own time zone, so a false one only costs a confirmation.
- **Limits.** Counted per account, across its phones and their key rotations, and enforced when charging, so authorizations collected in advance can't add up past them. Authorization mentions a limit already reached, so the person isn't asked to confirm a payment that would be refused.
- **Rate limits.** Each client address may make 40 requests a minute to the key and account routes and 60 to the payment routes.

## Audit log

The server appends an entry for every registration, refusal, rotation, removal, revocation, account change, decision, device recall mark, request check, and payment, in the same SQLite transaction as the change. Each entry's hash covers its fields, length-prefixed, and the previous entry's hash. The server checks the chain from the start at launch and logs the head hash outside the database; operators can check it at any time through `/admin/audit`. Changing, removing, or reordering an entry breaks the chain from that entry on.

**Checkpoints.** A chain alone doesn't catch someone who rewrites the whole table and recomputes every hash. So every ten minutes, and when an operator asks through `/admin/audit/checkpoint`, the server signs the head (entry number, hash, time) with an anchor key kept apart from the database and appends it to a checkpoint file outside it. With `TRUSTGATE_TSA_URL` set, an RFC 3161 timestamping authority also signs each checkpoint, and only tokens from its pinned certificates count. At launch and in `/admin/audit`, the server checks every checkpoint's signature and timestamp, and that the log still holds the recorded hash at that entry. To pass, a rewrite would also need the anchor key and a timestamp from before it happened.

Admin routes are served only when an operator token is configured, and compare it in constant time.

## Transport

The server serves HTTPS only, on the loopback interface by default. The app's network security config is generated per build and disallows cleartext: debug builds trust only the development server's own certificate for `10.0.2.2` and pin its key; release builds pin the keys given as Gradle properties. The development certificate, its password, the operator token, and the audit anchor key are generated on first run and never committed.

## On the phone

- **Storage:** values are sealed with AES-256-GCM under a Keystore key, with each value's name as associated data. A value that fails authentication is removed and reported. Backups are off and data extraction rules exclude stored values and the log.
- **Screens:** payment screens hide other apps' overlays (Android 12+) and ignore taps through them. Release builds also block screenshots, recording, and the recents thumbnail. The confirmation dialog filters obscured touches in its own window.
- **Code:** release builds are shrunk and obfuscated with R8. Nothing secret ships in the app.
- **Log:** the app's activity log explains each decision to the person, keeps the latest 150 events on the phone, and can be shared or cleared. The server's audit log is the record that counts.

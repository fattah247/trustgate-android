# Threat Model

## What TrustGate protects

A payment from a phone. The server should charge it only when the request really comes from a phone it registered, the phone and the app are what they claim to be, nobody has changed or replayed the request, and nothing suggests the person is being talked into it. When the network drops an answer, the payment must still be charged exactly once.

## Who attacks, and how

- **A scripted attacker with the protocol.** Knows every route and message, has a phone and a copy of the app, and can send any request. The [attack lab](ATTACK_LAB.md) plays this part against the real server.
- **Someone in the middle.** Can see, hold back, replay, or edit traffic, or present their own certificate.
- **A repackager.** Decompiles the app, changes it, and signs it with another key.
- **A phone the attacker controls.** Rooted, running an emulator, or instrumented, so the app's own checks may report whatever the attacker likes.
- **A scammer on the line.** Talks the real person into paying, often while sharing their screen or after getting them to install a remote-help app. The person passes every authentication check themselves.
- **Malware on the phone.** Reads or drives the screen through accessibility access or overlays.
- **Someone after the account.** Has a phone of their own and tries to add it to someone else's account, or to remove that person's phones.
- **A fraudster starting over.** Wipes a blocked phone, or sets it up as new, to shed its record and get fresh limits.
- **Someone with database access.** Edits what the server recorded after the fact.
- **Someone in the build.** Swaps a dependency, a CI action, or the release file between the commit and the person installing it.

## Threats, and what stops them

| Threat | Stopped by |
| --- | --- |
| Replaying a payment or any signed request | One-time server challenges, spent in the same transaction as the charge; a repeated payment returns the original result without charging again |
| Editing a request after signing | The signature covers method, path, timestamp, nonce, key ID, idempotency key, confirmation, and the body's hash |
| Approving one payment and sending another | The challenge is bound to the exact payment the server weighed; a different payee, amount, currency, or reference signed with it is refused |
| Holding a request back and sending it later | A five-minute window around arrival |
| Signing with an unregistered key, or another phone's challenge | Keys must be registered; each challenge is bound to one phone and one purpose |
| A repackaged app | The key attestation names the package and signing certificate; Play Integrity names the certificate and whether Google Play recognises the build |
| A key imported from outside Keystore, or held in software | The attestation's origin and security level, refused by the strict policy |
| A rooted phone or an unlocked bootloader | Verified boot and bootloader state from the attestation, checked against Google's pinned roots and revocation list; Play Integrity's device verdict |
| Lying on-phone checks | The server scores signals from its own catalog and weighs the attestation and Play Integrity, which the phone can't forge |
| A device report or integrity token for something else | The report is signed by the device key; the integrity token's request hash must be the report's hash |
| Skipping the confirmation | Medium risk needs the step-up key's signature, which only exists after real authentication; faking the prompt's callback produces nothing the server accepts |
| A step-up key slipped in, or removed to downgrade the phone | Adding or removing one needs the device key's signature |
| Remote-help and screen-sharing scams | Play Integrity's app-access verdict blocks while an app can control the screen; an active call, a non-tool accessibility service, or recording of the app's window asks for confirmation; each shows a scam warning |
| A payment unlike the account's own | A first payment to a payee, an amount far above the account's largest, or a payment at an hour it never pays asks for confirmation |
| Overlays and tapjacking | Other apps' overlays are hidden on payment screens (Android 12+), and taps through one are ignored |
| Draining an account quickly | A per-account cap on payments in a short window and on the daily amount, enforced when charging; new phones confirm every payment and may only pay small amounts for a day |
| Resetting limits with a new key or another phone | Limits follow the account across its phones and key rotations; a phone that starts over as new gets the new-phone rules |
| Wiping a blocked phone and starting again | Device recall keeps *blocked* and *set up here* on Google's side through a factory reset; a blocked phone stays blocked, and one set up again confirms its payments |
| Adding a phone to someone else's account | A one-time, 10-minute link code from a phone on the account, then approval signed by that phone's screen-lock key; the joining phone counts as new for a day |
| Removing someone else's phones | Only a phone on the same account can, with the same signed approval |
| Taking over a phone by rotating its key | Only the current key can vouch for its successor, and the successor must be attested at least as well |
| A stolen or compromised phone | The phone can remove itself, and an operator can revoke it; a revoked key is never accepted again |
| Flooding key registration or payments | Per-address rate limits on both route groups |
| Old, vulnerable app versions | A minimum version, checked at registration and at payment |
| A man in the middle | HTTPS only, pinned to the server's key |
| Editing the server's records | A hash-chained audit log, written with each change, checked at startup and on demand |
| Rewriting the whole log and recomputing every hash | Checkpoints of the head signed by a separate anchor key, kept outside the database, and optionally timestamped by an outside authority |
| Crafted input aimed at the parsers | The hand-written parsers for attestation chains, the revocation list, and integrity tokens are fuzzed with Jazzer; each input that broke one is kept as a regression test |
| A tampered dependency, action, or release file | Gradle checks every artifact against recorded checksums, actions are pinned to commits, and release builds carry signed provenance naming the repository, commit, and workflow |
| Double charging after a lost response | Idempotency keys scoped to the phone, with retries that resend the identical request |
| Leaking stored values | AES-GCM under a Keystore key; backups and transfers excluded; capture blocked on payment screens |

## What isn't covered

- **A phone that defeats hardware attestation and Play Integrity.** A leaked attestation key not yet on Google's revocation list, or a flaw in a phone's secure hardware, would let a phone pass as genuine. That's Google's and the phone maker's to fix; the strict policy narrows the window by requiring the revocation list, strong integrity, and recent patches.
- **A scam the person goes through with.** Warnings, habit checks, confirmations, and limits slow it down; they can't stop someone who keeps saying yes. That needs fraud analytics across accounts, cooling-off periods on new payees, and confirmation of payee, which belong to a real payment service.
- **Who an account belongs to.** Phones join accounts only with approval, but nothing ties an account to a person, and there's no way back in once every phone on it is lost. That belongs to the host app's login and recovery.
- **A compromised server.** The server is the authority. Checkpoints show a rewrite of what it already logged, but someone in full control of the running server, with its anchor key, can log falsely from then on.

## Trust boundaries

- **The phone and the app process:** untrusted. Useful for collecting evidence and for the person's view, never for the decision.
- **Android Keystore and secure hardware:** trusted to keep keys unexportable and to attest truthfully, as vouched for by Google's roots.
- **Google Play Integrity:** trusted for its verdict, checked on the server against the request it was issued for.
- **The server:** the authority for every decision, key, and charge.

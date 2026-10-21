# Attack Lab

Two ways to attack TrustGate and watch it refuse: the Lab tab in the app, and a harness that talks to the server directly. Both aim at the server, because its answer is the only one that counts. Neither changes the app or the phone it runs on.

## In the app

The Lab tab signs real requests with the phone's own key and sends them to the server altered:

| Test | What it sends | What the server says |
| --- | --- | --- |
| Replay a request | One signed request, twice | Accepts the first, refuses the second: the challenge was already used |
| Change the amount | A signed request whose amount was raised after signing | Refused: the signature doesn't cover the new body |
| Send it late | A request signed just outside the five-minute window | Refused: too late |
| Pay 6 times at once | Six authorizations collected first, then six payments as fast as possible | Pays up to the limit, then refuses: too many payments |

The same tab can lose the first reply to a payment (the app retries and the server charges once), replace the phone's key, and remove the phone. In debug builds without Play, it can also pretend Google Play's verdict found a remote-control app, a screen recorder, harmful apps, an unlicensed copy, or, through device recall, a phone that was set up here or blocked before.

**Phones on this account** lists the account's phones and lets one join: Add another phone makes a code, the other phone enters it under Join another account, and the first phone approves it with its screen lock, or a signed tap on a phone without one. To try it with one emulator, make a code in the app and play the second phone from the harness:

```bash
./gradlew :server:joinAccount -Pcode=CODE
```

The app then shows "Second phone (lab)" waiting for approval.

On Home, paying the seller you haven't paid before, or the largest amount, shows the habit checks asking for confirmation once the account has some history.

## The harness

`./gradlew :server:attackLab` runs a client that knows the protocol and has keys of its own, against the server started by `./gradlew :server:run`. It connects over HTTPS that trusts only the development server's certificate, prints what each attack got back, and exits non-zero if anything gets through.

```bash
./gradlew :server:run          # in one terminal
./gradlew :server:attackLab    # in another
```

Against the development policy:

```text
STOPPED      Replay a payment                                    Same payment returned, charged once
STOPPED      Pay more than was approved                          Refused: payment_changed
STOPPED      Raise the amount after signing                      Refused: signature_mismatch
STOPPED      Deliver a request after the time window             Refused: outside_time_window
STOPPED      Sign with a key the server never registered         Refused: unknown_key
STOPPED      Use a challenge issued to another phone             Refused: unknown_challenge
STOPPED      Send a clean device report signed by another key    Report not signed by this phone
STOPPED      Reuse an integrity token issued for another report  Play Integrity check was for a different request
STOPPED      Pay without the confirmation the server asked for   Refused: confirmation_required
STOPPED      Add a confirmation key the phone didn't approve     Refused: The device key didn't vouch for this step-up key.
STOPPED      Take over a phone by replacing its key              Refused: The current key didn't vouch for the new one.
STOPPED      Keep using a key after it was replaced              Refused: key_revoked
STOPPED      Join an account by guessing its code                That code isn't valid. Make a new one on your other phone.
STOPPED      Let a phone in from off the account                 HTTP 403
STOPPED      Remove a phone from someone else's account          HTTP 403
STOPPED      Pay 6 times as fast as possible                     3 paid, then refused: too_many_payments
STOPPED      Read the audit log without the operator token       HTTP 401
STOPPED      Flood key registration                              Slowed down after 10 requests (HTTP 429)

18 of 18 attacks stopped.
```

Against the strict policy (`./gradlew :server:run -Ptrustgate.policy=strict`), the harness can't even register: its keys are software keys with no hardware attestation, which is the point.

```text
STOPPED      Register a key with no hardware proof          This backend accepts only attested keys.
SKIPPED      The attacks that need a registered key         This server registers only hardware-attested keys
STOPPED      Read the audit log without the operator token  HTTP 401
```

The rate limits count per minute, so wait a minute between runs.

`AttackLabTest` runs the same attacks against the server's routes in process on every build, so a change that lets one through fails the tests, not just a manual run.

## Attacks on the phone itself

A phone the attacker controls is a different kind of attack: they can root it, change the app, or instrument it so the app's own checks report whatever they like. TrustGate doesn't try to win that fight on the phone. The server instead relies on what such a phone can't forge:

- **Key attestation**, signed by the phone's secure hardware up to Google's roots, which says whether the bootloader is locked, the system verified, and the key generated in hardware for this app's package and signing certificate.
- **The Play Integrity verdict**, which Google signs and the server decodes, bound to the exact report the phone signed.

A repackaged or instrumented app still has to present both, and the strict policy refuses payments without them. See [THREAT_MODEL.md](THREAT_MODEL.md) for what remains out of reach.

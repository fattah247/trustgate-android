# Security Policy

TrustGate is a reference project for mobile payment security. If you find a way past one of its protections, I'd like to hear about it.

## Reporting a vulnerability

Please report it privately through GitHub's **Report a vulnerability** button on the repository's Security tab, rather than in a public issue. Include what you did, what you expected the server to refuse, and what it accepted instead. The attack lab (`./gradlew :server:attackLab`) is a good starting point for a reproduction.

I'll acknowledge a report within a week and keep you posted on the fix.

## Scope

In scope: anything that gets a payment, key registration, rotation, or removal past the server's checks, a way to edit the audit log without the chain showing it, and anything that leaks stored values or keys from the app.

Out of scope: findings that need a phone the attacker already fully controls to lie about itself when its hardware attestation and Play Integrity verdict say otherwise, as described in [docs/LIMITATIONS.md](docs/LIMITATIONS.md), and the development policy's relaxations, which exist for emulators.

## Supported versions

Only the latest commit on `main` is supported.

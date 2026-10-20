# Supply Chain

What keeps a dependency, a build tool, or a CI action from becoming the way in.

## Dependencies

- **Checksums for every artifact.** `gradle/verification-metadata.xml` records the SHA-256 of every library, plugin, and build tool the build downloads, including Android's `aapt2` for Linux, macOS, and Windows. Gradle refuses an artifact whose checksum doesn't match, so a tampered or substituted download fails the build instead of running in it. Sources and Javadoc jars, which an IDE fetches but the build never runs, are trusted without a checksum.
- **Exact versions.** Every dependency names one version; nothing resolves to "latest".
- **Known vulnerabilities.** The `security` workflow submits the resolved Gradle dependency graph to GitHub, which drives Dependabot alerts and the SBOM GitHub can export for the repository. On pull requests, dependency review fails a change that adds a dependency with a known vulnerability of moderate severity or worse.
- **Updates.** Dependabot opens weekly pull requests for Gradle dependencies and GitHub Actions.

### After changing a dependency

A new or updated dependency needs its checksums recorded before the build will accept it, Dependabot's pull requests included. Check the change is the one you meant, then run:

```bash
./gradlew --write-verification-metadata sha256 -I gradle/platform-artifacts.init.gradle.kts \
  resolveAapt2Platforms test assembleDebug assembleRelease lint
```

The init script resolves `aapt2` for every platform so a build on one operating system records the checksums the others need. Review the diff to `gradle/verification-metadata.xml` like code: every new entry is something the build will run.

## The Gradle wrapper

`gradle/actions/setup-gradle` checks `gradle-wrapper.jar` against the checksums Gradle publishes before any build runs in CI.

## CI

- **Actions pinned to commits.** Every action is referenced by its full commit SHA, with the release tag in a comment, so a moved or compromised tag can't change what runs. Dependabot updates both together.
- **Least privilege.** Workflows default to read-only contents. Only the jobs that upload code-scanning results get `security-events: write`, only dependency submission gets `contents: write`, and only Scorecard gets an OIDC token. Checkouts don't keep the token in the repository's Git config.
- **Static analysis.** CodeQL runs its extended security queries on Kotlin and Java for every pull request, on `main`, and weekly. mobsfscan runs Android-specific rules on the app. Both report to GitHub code scanning.
- **Scorecard.** The OpenSSF Scorecard workflow grades the repository's own practices (pinning, permissions, branch protection, reviews) and publishes the result.

## Secrets

Nothing secret is committed. The development server's TLS key, its password, and the operator token are generated into `server/build/dev-tls` the first time the server runs. Release signing keys, Play Integrity credentials, and production pins come from the environment or Gradle properties at build time.

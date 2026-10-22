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
- **Least privilege.** Workflows default to read-only contents. Only the jobs that upload code-scanning results get `security-events: write`, only dependency submission gets `contents: write`, and only Scorecard and the provenance build get an OIDC token. Checkouts don't keep the token in the repository's Git config.
- **Static analysis.** CodeQL runs its extended security queries on Kotlin and Java for every pull request, on `main`, and weekly. mobsfscan runs Android-specific rules on the app. Both report to GitHub code scanning.
- **Scorecard.** The OpenSSF Scorecard workflow grades the repository's own practices (pinning, permissions, branch protection, reviews) and publishes the result.
- **Fuzzing.** The `fuzz` workflow runs Jazzer against each hand-written parser for outside input: the attestation DER reader, key descriptions, certificate chains, the revocation list, and mock integrity tokens. It runs nightly and on pushes to `main`, two minutes per parser, and uploads any input that breaks one.

### Fuzzing locally

Without `JAZZER_FUZZ`, the fuzz tests run only their saved inputs, as part of `./gradlew test`. To fuzz one parser:

```bash
JAZZER_FUZZ=1 ./gradlew :backend:test --tests "*ParserFuzzTest.keyDescription" --rerun
```

A finding is saved as `backend/crash-…`. Fix the parser, then move the input under `backend/src/test/resources/id/fatarc/trustgate/backend/fuzz/ParserFuzzTestInputs/<test>/`, where every later build replays it.

## Build provenance

The `provenance` workflow builds the release APK and the server bundle on every push to `main` and on version tags, without the Gradle cache, and has GitHub sign [SLSA build provenance](https://slsa.dev/spec/v1.0/provenance) for both. Each attestation names the file's SHA-256, the repository, the commit, and the workflow that built it, and is signed with a short-lived Sigstore certificate issued to that workflow run. The files and their checksums are uploaded with the run.

To check a downloaded file came from this repository's workflow:

```bash
gh attestation verify trustgate-server.zip   --repo fattah247/trustgate-android   --signer-workflow fattah247/trustgate-android/.github/workflows/provenance.yml   --source-ref refs/heads/main   --deny-self-hosted-runners
```

A file changed after the build, or built anywhere else, has no attestation that matches.

## Secrets

Nothing secret is committed. The development server's TLS key, its password, the operator token, and the audit anchor key are generated into `server/build/dev-tls` the first time the server runs. Release signing keys, Play Integrity credentials, the production anchor key, and production pins come from the environment or Gradle properties at build time.

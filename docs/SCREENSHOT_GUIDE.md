# Screenshot Guide

Capture screenshots only from a working app, a real command run, or a live GitHub page.

| Filename | Screen or command | What it proves | Capture notes |
| --- | --- | --- |
| `docs/screenshots/01-app-overview.png` | Overview | The app launches and shows current trust state, recent audit history, and bottom navigation | Cold-start the app on the emulator and capture the overview without system dialogs on screen. |
| `docs/screenshots/02-device-risk-details.png` | Signals | Risk signals are visible with severity and explanation | Open the `Signals` tab and capture the first visible risk cards. |
| `docs/screenshots/03-sensitive-action-allowed.png` | Sensitive Action Gate on `LOW` | Low-risk scenario allows the protected action | Open `Gate`, choose `Sensitive Action Gate`, select `Low risk`, run `Run protected action`, and capture the allowed decision state. |
| `docs/screenshots/04-sensitive-action-blocked.png` | Sensitive Action Gate on `HIGH` | High-risk scenario blocks the protected action | Open `Gate`, choose `Sensitive Action Gate`, select `High risk`, run `Run protected action`, and capture the blocked decision state. |
| `docs/screenshots/05-request-signing-reference.png` | Request Signing | Signed headers, nonce, timestamp, and body hash are shown | Open `Gate`, choose `Request Signing`, tap `Sign reference request`, and scroll until the signed request fields are visible. |
| `docs/screenshots/06-secure-storage-reference.png` | Secure Storage | Reference values are stored and visible in the UI | Open `Gate`, choose `Secure Storage`, tap `Store reference values`, and capture the stored values section. |
| `docs/screenshots/07-security-event-log.png` | Security Event Log | Event trail records assessments and decisions | Capture after visiting the protected action, signing, and storage workflows so the log contains varied events. |
| `docs/screenshots/08-tests-passing.png` | `./gradlew test --console=plain` output | Unit tests pass | Use a fresh successful test run and capture the real command output, including `BUILD SUCCESSFUL`. |
| `docs/screenshots/09-ci-passing.png` | GitHub Actions run summary | CI is green on the repository | Capture the successful `Android CI` summary page for the screenshot branch so the branch name, status, and jobs are visible. |
| `docs/screenshots/10-repo-overview.png` | GitHub branch page | Public repo structure and docs are in place | Capture the branch tree view on GitHub so the branch selector, folders, and README preview are visible together. |

# Screenshot Guide

Capture screenshots only from a working app, a real command run, or a live GitHub page.

| Filename | Screen or command | What it proves | Capture notes |
| --- | --- | --- |
| `docs/screenshots/01-app-overview.png` | Home / Trust Overview | The app launches and shows current trust state | Cold-start the app on the emulator and capture the overview without system dialogs on screen. |
| `docs/screenshots/02-device-risk-details.png` | Device Risk Details | Risk signals are visible with severity and explanation | Open `Device Risk Details` from the overview and capture the first visible risk cards. |
| `docs/screenshots/03-sensitive-action-allowed.png` | Payment Action Demo on `LOW` | Low-risk device allows the action | In the payment demo, select the `Low` demo risk, run `Create demo payment`, and capture the updated `Latest decision`. |
| `docs/screenshots/04-sensitive-action-blocked.png` | Payment Action Demo on `HIGH` | High-risk device blocks the action | In the payment demo, select the `High` demo risk, run `Create demo payment`, and capture the blocked decision state. |
| `docs/screenshots/05-request-signing-demo.png` | Request Signing Demo | Signed headers, nonce, timestamp, and body hash are shown | Tap `Sign demo request` first so the signed request fields and canonical body are visible. |
| `docs/screenshots/06-secure-storage-demo.png` | Secure Storage Demo | Mock values are stored and visible in the UI | Tap `Store demo values` before capture so the encrypted values and confirmation message are populated. |
| `docs/screenshots/07-security-event-log.png` | Security Event Log | Event trail records assessments and decisions | Capture after visiting the payment, signing, and storage demos so the log contains varied events. |
| `docs/screenshots/08-tests-passing.png` | `./gradlew test --console=plain` output | Unit tests pass | Use a fresh successful test run and capture the real command output, including `BUILD SUCCESSFUL`. |
| `docs/screenshots/09-ci-passing.png` | GitHub Actions run summary | CI is green on the repository | Capture the successful `Android CI` summary page for the screenshot branch so the branch name, status, and jobs are visible. |
| `docs/screenshots/10-repo-overview.png` | GitHub branch page | Public repo structure and docs are in place | Capture the branch tree view on GitHub so the branch selector, folders, and README preview are visible together. |

# Screenshot Guide

Capture screenshots only from a working app, a real command run, or a live GitHub page.

| Filename | Screen or command | What it proves | Capture notes |
| --- | --- | --- | --- |
| `docs/screenshots/01-app-overview.png` | Overview | The app launches and shows current trust state, recent audit history, and bottom navigation | Cold-start the app on the emulator and capture the overview without system dialogs on screen. |
| `docs/screenshots/02-device-risk-details.png` | Signals | The verdict is explained with its rule and point breakdown | Open the `Signals` tab and capture the summary and the `Why` section. |
| `docs/screenshots/03-sensitive-action-allowed.png` | Sensitive action on `Low` | Low-risk profile allows the protected action, and a lost response is retried without charging twice | Open `Gate`, choose `Sensitive action`, select `Low` under `Risk source`, turn on `Lose the first response`, tap `Run protected action`, and capture the allowed result with its payment ID. |
| `docs/screenshots/04-sensitive-action-blocked.png` | Sensitive action on `High` | High-risk profile blocks the protected action | Open `Gate`, choose `Sensitive action`, select `High` under `Risk source`, tap `Run protected action`, and capture the blocked result. |
| `docs/screenshots/05-request-signing-reference.png` | Request signing | The backend accepting a genuine request while rejecting replayed, edited, and late ones | Open `Gate`, choose `Request signing`, tap `Sign a new request`, then send it as signed twice, with a changed amount, and after the time window, and capture `Backend responses`. |
| `docs/screenshots/06-secure-storage-reference.png` | Secure storage | Reference values are stored and visible in the UI | Open `Gate`, choose `Secure storage`, tap `Save reference values`, and capture the stored values section. |
| `docs/screenshots/07-security-event-log.png` | Activity | Event trail records assessments and decisions | Open the `Activity` tab after visiting the protected action, signing, and storage workflows so the log contains varied events. |
| `docs/screenshots/08-tests-passing.png` | `./gradlew test --console=plain` output | Unit tests pass | Use a fresh successful test run and capture the real command output, including `BUILD SUCCESSFUL`. |
| `docs/screenshots/09-ci-passing.png` | GitHub Actions run summary | CI is green on the repository | Capture the successful `Android CI` summary page for the screenshot branch so the branch name, status, and jobs are visible. |
| `docs/screenshots/10-repo-overview.png` | GitHub branch page | Public repo structure and docs are in place | Capture the branch tree view on GitHub so the branch selector, folders, and README preview are visible together. |
| `docs/screenshots/11-device-keys.png` | Request signing | Both Keystore keys registered from their attestation | Set a screen lock PIN first so the step-up key exists. Open `Gate`, choose `Request signing`, and capture `Device keys`. |

## Demo GIF

`docs/demo.gif` is assembled from real screen captures (`adb exec-out screencap`) taken during one run of the flow in screenshot 03, followed by `Inspect request`. A ring marks each tap. The capture uses the System UI demo mode status bar, light theme, and font scale 1.0.

# Screenshot Guide

Capture screenshots only from a working app, a real command run, or a live GitHub page.

Phone screenshots come from the emulator in light theme at font scale 1.0, with System UI demo mode for a clean status bar, using the debug build against `./gradlew :server:run`. Start from a cleared app (`adb shell pm clear id.fatarc.trustgate`) so Activity holds only this session. The development server allows 3 payments a minute, so wait a minute after the Lab's rapid test before paying again.

| Filename | Screen or command | What it shows | Capture notes |
| --- | --- | --- | --- |
| `01-home.png` | Home | This phone's real checks and the checkout card | Cold-start the app; on an emulator the checks block payments. |
| `02-checks.png` | Checks | What was found, what passed, and the risk level | Open the Checks tab. |
| `03-paid-after-lost-reply.png` | Pay | A payment charged once after its first reply was lost | In Lab, turn on Lose the first reply. On Home, pick A safe phone and pay. |
| `04-confirm-payment.png` | Confirmation | The server asking for the person's OK, and why | Turn Lose the first reply off, pick A risky phone, and pay. On an emulator without a screen lock this is the tap dialog. |
| `05-blocked-scam-warning.png` | Pay | A payment blocked by Play Integrity's app-access verdict, with the scam warning and the fix | In Lab, set Pretend Google Play found to A remote-control app running; pick A safe phone and pay. Set it back to Nothing unusual afterwards. |
| `06-lab-attacks-stopped.png` | Lab | Each attack refused by the server | Run all four tests in Try to break it. |
| `07-what-was-sent.png` | What was sent | The last signed request, field by field | Lab, What was sent last. |
| `08-phone-key.png` | Phone key | The key's attestation as the server registered it, and Replace this key | Lab, Phone key; scroll the sheet to the button. |
| `09-ci-passing.png` | GitHub Actions | CI green on `main` | The run summary for the latest push to `main`, with the branch, status, and jobs visible. |
| `10-repo-overview.png` | GitHub | The repository and its README | The branch tree view with the README preview. Check the contributor list and latest-commit row. |
| `11-activity.png` | Activity | The log of checks, payments, and Lab tests | Open the Activity tab after the steps above. |
| `12-tests-passing.png` | `./gradlew test --no-build-cache --console=plain` | Every module's tests passing | Run `cleanTest`, `:app:cleanTestDebugUnitTest`, and `:app:cleanTestReleaseUnitTest` first so every test runs. Rendered from the command's output, with the test count from the JUnit reports, counting the app's tests once although they run for debug and release. |
| `13-attack-lab.png` | `./gradlew :server:attackLab` | The harness's attacks against the running server | Run against `./gradlew :server:run`, rendered from the command's output. |

## Demo GIF

`docs/demo.gif` is assembled from real screen captures (`adb exec-out screencap`) taken during one payment on a safe demo phone, followed by See what was sent. A ring marks each tap.

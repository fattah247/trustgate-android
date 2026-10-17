package id.fatarc.trustgate.ui.about

import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.BuildConfig
import id.fatarc.trustgate.ui.BulletItem
import id.fatarc.trustgate.ui.ScreenScaffold
import id.fatarc.trustgate.ui.Section
import id.fatarc.trustgate.ui.TrustGateUiState

@Composable
fun AboutScreen(
    uiState: TrustGateUiState,
    onNavigateUp: () -> Unit,
) {
    ScreenScaffold(
        title = "About TrustGate",
        onNavigateUp = onNavigateUp,
    ) {
        item(key = "intro") {
            Text(
                text = "A device-integrity lab. It connects client-side checks to protected actions, request " +
                    "signing, and a local audit trail. It doesn't replace server-side enforcement.",
                modifier = Modifier.padding(horizontal = 16.dp),
                style = MaterialTheme.typography.bodyLarge,
            )
        }

        item(key = "covers") {
            Section(title = "What it covers") {
                Spacer(Modifier.height(6.dp))
                BulletItem("Runtime signals for root access, emulation, debugging, and install source.")
                BulletItem("A risk level the backend turns into a decision: run, ask to confirm, or stop.")
                BulletItem("Keystore keys, attested to the backend, that sign each request; the step-up key only signs after biometrics or the screen lock.")
                BulletItem("One-time challenges and idempotent payments, so replays are refused and retries never charge twice.")
                BulletItem("A local event log so each check and decision can be reviewed later.")
                Spacer(Modifier.height(6.dp))
            }
        }

        item(key = "limits") {
            Section(title = "Limits") {
                Spacer(Modifier.height(6.dp))
                BulletItem("Client-side checks are signals, not proof that a device can be trusted.")
                BulletItem("The reference backend runs inside the app, so it shows what a server checks but isn't an independent authority.")
                BulletItem("There's no Play Integrity verdict, payment processor, or fraud engine behind the demo flow.")
                BulletItem("Advanced hooking frameworks and kernel-level compromise are out of scope.")
                Spacer(Modifier.height(6.dp))
            }
        }

        item(key = "pinning") {
            Section(
                title = "Certificate pinning",
                footer = "Version ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})",
            ) {
                Text(
                    text = if (uiState.pinning.enabled) {
                        "Pinning is on for ${uiState.pinning.host}. A real deployment also needs a plan for rotating pins."
                    } else {
                        "Pinning for ${uiState.pinning.host} is written but turned off, so this build works without a pinned server."
                    },
                    modifier = Modifier.padding(16.dp),
                    style = MaterialTheme.typography.bodyLarge,
                )
            }
        }
    }
}

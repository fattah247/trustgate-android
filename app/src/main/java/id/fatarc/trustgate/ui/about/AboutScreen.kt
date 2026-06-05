package id.fatarc.trustgate.ui.about

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import id.fatarc.trustgate.ui.BulletLine
import id.fatarc.trustgate.ui.SectionCard
import id.fatarc.trustgate.ui.TrustGateScreen
import id.fatarc.trustgate.ui.TrustGateUiState

@Composable
fun AboutScreen(
    uiState: TrustGateUiState,
) {
    TrustGateScreen {
        item {
            SectionCard(title = "What this app demonstrates") {
                Text(
                    text = "TrustGate Android is a public-safe mobile security lab. It shows how a client can collect runtime risk signals, gate a sensitive action, sign a request, and keep a local event trail.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }

        item {
            SectionCard(title = "Limits of the demo") {
                BulletLine("Client-side checks are signals, not guarantees of trustworthiness.")
                BulletLine("The request-signing key is hardcoded because this is a demonstration, not production custody.")
                BulletLine("There is no real payment processor, fraud engine, or server-side adjudication behind the flow.")
                BulletLine("Kernel-level compromise and advanced bypass frameworks remain out of scope.")
            }
        }

        item {
            SectionCard(title = "Certificate pinning note") {
                Text(
                    text = uiState.pinningSummary,
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    text = "Pinning can reduce some man-in-the-middle risk, but it still depends on certificate rotation planning and server-side controls.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

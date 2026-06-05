package id.fatarc.trustgate.ui.about

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import id.fatarc.trustgate.ui.BulletLine
import id.fatarc.trustgate.ui.DetailSurface
import id.fatarc.trustgate.ui.SectionBlock
import id.fatarc.trustgate.ui.SummaryPanel
import id.fatarc.trustgate.ui.TrustGateScreen
import id.fatarc.trustgate.ui.TrustGateUiState

@Composable
fun AboutScreen(
    uiState: TrustGateUiState,
) {
    TrustGateScreen {
        item {
            SummaryPanel(
                eyebrow = "Scope",
                title = "A device-integrity lab, not a full trust platform",
                supporting = "TrustGate Android demonstrates how client-side checks, protected actions, request signing, and local audit output fit together. It does not replace server-side enforcement.",
            )
        }

        item {
            SectionBlock(
                title = "What this app demonstrates",
                description = "The current build focuses on a small set of mobile security workflows that can be reviewed end to end.",
            ) {
                DetailSurface {
                    BulletLine("Collect runtime signals that suggest root access, emulation, debugging, or unusual install context.")
                    BulletLine("Map those signals to a simple trust result that can guide protected app behavior.")
                    BulletLine("Record local events so test runs and device states can be reviewed later.")
                    BulletLine("Show how request signing and encrypted local storage fit into the same client security story.")
                }
            }
        }

        item {
            SectionBlock(
                title = "Operational limits",
                description = "These limits matter when interpreting the result in real-world environments.",
            ) {
                DetailSurface {
                    BulletLine("Client-side checks are signals, not guarantees of trustworthiness.")
                    BulletLine("The signing key is hardcoded because this screen demonstrates request shape, not production key custody.")
                    BulletLine("There is no real payment processor, fraud engine, or server-side adjudication behind the demo flow.")
                    BulletLine("Advanced bypass frameworks and kernel-level compromise remain out of scope.")
                }
            }
        }

        item {
            SectionBlock(
                title = "Certificate pinning note",
                description = "Pinning helps narrow transport risk, but it does not remove the need for backend validation and certificate operations.",
            ) {
                DetailSurface {
                    Text(
                        text = uiState.pinningSummary,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
    }
}

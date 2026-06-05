package id.fatarc.trustgate.ui.risk

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.foundation.lazy.items
import id.fatarc.trustgate.ui.CalloutTone
import id.fatarc.trustgate.ui.KeyValueRow
import id.fatarc.trustgate.ui.RiskBadge
import id.fatarc.trustgate.ui.SectionCard
import id.fatarc.trustgate.ui.StatusCallout
import id.fatarc.trustgate.ui.StatusCalloutState
import id.fatarc.trustgate.ui.TrustGateScreen
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.asHumanLabel
import id.fatarc.trustgate.ui.asLabel

@Composable
fun DeviceRiskDetailsScreen(
    uiState: TrustGateUiState,
) {
    val report = uiState.risk.report
    TrustGateScreen {
        item {
            SectionCard(title = "Assessment notes") {
                Text(
                    text = "These client checks are heuristics. They help route sensitive actions, but they are not proof of device integrity.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (report != null) {
                    RiskBadge(level = report.level)
                    KeyValueRow(label = "Risk level", value = report.level.asLabel())
                    KeyValueRow(label = "Risk score", value = report.score.toString())
                    KeyValueRow(label = "Assessed at", value = report.assessedAt.toString(), monospace = true)
                } else {
                    StatusCallout(
                        state = StatusCalloutState(
                            title = "No risk report available",
                            body = uiState.risk.errorMessage ?: "Run a live assessment from the overview screen first.",
                            tone = if (uiState.risk.errorMessage == null) CalloutTone.NEUTRAL else CalloutTone.ERROR,
                        ),
                    )
                }
            }
        }

        if (report != null) {
            items(report.signals, key = { it.id }) { signal ->
                SectionCard(title = signal.name) {
                    StatusCallout(
                        state = StatusCalloutState(
                            title = if (signal.detected) "Signal detected" else "Signal clear",
                            body = signal.explanation,
                            tone = if (signal.detected) CalloutTone.WARNING else CalloutTone.SUCCESS,
                        ),
                    )
                    KeyValueRow(label = "Category", value = signal.category.name.asHumanLabel())
                    KeyValueRow(label = "Severity", value = signal.severity.name.asHumanLabel())
                    KeyValueRow(label = "Signal id", value = signal.id, monospace = true)
                }
            }
        }
    }
}

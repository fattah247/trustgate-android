package id.fatarc.trustgate.ui.events

import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.ui.CalloutTone
import id.fatarc.trustgate.ui.DetailSurface
import id.fatarc.trustgate.ui.DividerList
import id.fatarc.trustgate.ui.EvidenceRow
import id.fatarc.trustgate.ui.KeyValueRow
import id.fatarc.trustgate.ui.RiskBadge
import id.fatarc.trustgate.ui.SectionBlock
import id.fatarc.trustgate.ui.SectionDivider
import id.fatarc.trustgate.ui.StatusCallout
import id.fatarc.trustgate.ui.StatusCalloutState
import id.fatarc.trustgate.ui.SummaryPanel
import id.fatarc.trustgate.ui.TrustGateScreen
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.asHumanLabel

@Composable
fun SecurityEventLogScreen(
    uiState: TrustGateUiState,
) {
    val events = uiState.securityEvents.asReversed()
    TrustGateScreen {
        item {
            SummaryPanel(
                eyebrow = "Local audit trail",
                title = if (events.isEmpty()) "No events recorded yet" else "${events.size} events recorded locally",
                supporting = if (events.isEmpty()) {
                    "Run a device assessment or complete one of the demo flows to populate the local event trail."
                } else {
                    "Each entry explains what the app assessed or allowed, and when that result was recorded on this device."
                },
                tone = if (events.isEmpty()) CalloutTone.NEUTRAL else CalloutTone.SUCCESS,
            )
        }

        if (events.isEmpty()) {
            item {
                StatusCallout(
                    state = StatusCalloutState(
                        title = "No activity yet",
                        body = "The event log will populate after the app records an assessment, action decision, signing event, or storage update.",
                    ),
                )
            }
        } else {
            item {
                SectionBlock(
                    title = "Recorded events",
                    description = "Entries are shown from newest to oldest.",
                ) {
                    DetailSurface {
                        DividerList {
                            events.forEachIndexed { index, event ->
                                EventRow(event = event)
                                if (index != events.lastIndex) {
                                    SectionDivider()
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun EventRow(event: SecurityEvent) {
    DividerList {
        EvidenceRow(
            title = event.type.name.asHumanLabel(),
            summary = event.message,
            trailing = {
                event.riskLevel?.let { riskLevel ->
                    RiskBadge(level = riskLevel)
                }
            },
        )
        KeyValueRow(label = "Recorded at", value = event.timestamp, monospace = true)
        event.metadata.toSortedMap().forEach { (key, value) ->
            KeyValueRow(
                label = key.asHumanLabel(),
                value = value,
                monospace = key.contains("nonce", ignoreCase = true) || key.contains("signature", ignoreCase = true),
            )
        }
    }
}

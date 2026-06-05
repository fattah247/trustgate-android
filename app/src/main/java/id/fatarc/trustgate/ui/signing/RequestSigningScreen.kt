package id.fatarc.trustgate.ui.signing

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.text.font.FontFamily
import id.fatarc.trustgate.ui.CalloutTone
import id.fatarc.trustgate.ui.DetailSurface
import id.fatarc.trustgate.ui.DividerList
import id.fatarc.trustgate.ui.KeyValueRow
import id.fatarc.trustgate.ui.PrimaryActionButton
import id.fatarc.trustgate.ui.SectionBlock
import id.fatarc.trustgate.ui.SectionDivider
import id.fatarc.trustgate.ui.SigningStatus
import id.fatarc.trustgate.ui.StatusCalloutState
import id.fatarc.trustgate.ui.SummaryPanel
import id.fatarc.trustgate.ui.TrustGateScreen
import id.fatarc.trustgate.ui.TrustGateUiState

@Composable
fun RequestSigningScreen(
    uiState: TrustGateUiState,
    onSignDemoRequest: () -> Unit,
) {
    val signingState = signingStateSummary(uiState.signing.status)
    TrustGateScreen {
        item {
            SummaryPanel(
                eyebrow = "Request signing",
                title = signingState.title,
                supporting = signingState.body,
                tone = signingState.tone,
            ) {
                PrimaryActionButton(
                    label = "Sign demo request",
                    onClick = onSignDemoRequest,
                )
            }
        }

        item {
            SectionBlock(
                title = "Signing model",
                description = "The client signs a demo request with a local HMAC key to show canonicalization, hashing, and header shape. It does not represent production key custody.",
            ) {
                DetailSurface {
                    Text(
                        text = "Use this screen to inspect the exact payload, timestamp, nonce, and derived headers that would be sent with a protected request.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }

        uiState.signing.signedRequest?.let { request ->
            item {
                SectionBlock(
                    title = "Signed request",
                    description = "These values come from the latest locally signed request.",
                ) {
                    DetailSurface {
                        DividerList {
                            KeyValueRow(label = "Amount", value = request.payload.amountMinor.toString())
                            SectionDivider()
                            KeyValueRow(label = "Currency", value = request.payload.currency)
                            SectionDivider()
                            KeyValueRow(label = "Reference", value = request.payload.merchantReference)
                            SectionDivider()
                            KeyValueRow(label = "Timestamp", value = request.timestamp, monospace = true)
                            SectionDivider()
                            KeyValueRow(label = "Nonce", value = request.nonce, monospace = true)
                            SectionDivider()
                            KeyValueRow(label = "Body hash", value = request.bodyHash, monospace = true)
                            request.headers.toSortedMap().forEach { (name, value) ->
                                SectionDivider()
                                KeyValueRow(label = name, value = value, monospace = true)
                            }
                        }
                    }
                }
            }
            item {
                SectionBlock(
                    title = "Canonical body",
                    description = "This is the exact serialized payload used to derive the body hash.",
                ) {
                    DetailSurface {
                        Text(
                            text = request.canonicalBody,
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }
    }
}

private fun signingStateSummary(status: SigningStatus): StatusCalloutState {
    return when (status) {
        SigningStatus.Idle -> StatusCalloutState(
            title = "No request signed yet",
            body = "Generate a demo request to inspect the canonical payload, body hash, and derived headers.",
        )

        is SigningStatus.Signed -> StatusCalloutState(
            title = "Request signed",
            body = "The latest request for ${status.merchantReference} was canonicalized and signed locally.",
            tone = CalloutTone.SUCCESS,
        )

        is SigningStatus.Failed -> StatusCalloutState(
            title = "Signing failed",
            body = status.message,
            tone = CalloutTone.ERROR,
        )
    }
}

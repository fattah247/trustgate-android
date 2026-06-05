package id.fatarc.trustgate.ui.signing

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.text.font.FontFamily
import id.fatarc.trustgate.ui.CalloutTone
import id.fatarc.trustgate.ui.KeyValueRow
import id.fatarc.trustgate.ui.PrimaryActionButton
import id.fatarc.trustgate.ui.SectionCard
import id.fatarc.trustgate.ui.SigningStatus
import id.fatarc.trustgate.ui.StatusCallout
import id.fatarc.trustgate.ui.StatusCalloutState
import id.fatarc.trustgate.ui.TrustGateScreen
import id.fatarc.trustgate.ui.TrustGateUiState

@Composable
fun RequestSigningScreen(
    uiState: TrustGateUiState,
    onSignDemoRequest: () -> Unit,
) {
    TrustGateScreen {
        item {
            SectionCard(title = "Signing model") {
                Text(
                    text = "The app signs a fake payment request with a demo-only local HMAC key. This demonstrates canonicalization and header shape, not production key custody.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                PrimaryActionButton(
                    label = "Sign demo request",
                    onClick = onSignDemoRequest,
                )
                StatusCallout(state = signingStateSummary(uiState.signing.status))
            }
        }

        uiState.signing.signedRequest?.let { request ->
            item {
                SectionCard(title = "Signed request") {
                    KeyValueRow(label = "Amount", value = request.payload.amountMinor.toString())
                    KeyValueRow(label = "Currency", value = request.payload.currency)
                    KeyValueRow(label = "Reference", value = request.payload.merchantReference)
                    KeyValueRow(label = "Timestamp", value = request.timestamp, monospace = true)
                    KeyValueRow(label = "Nonce", value = request.nonce, monospace = true)
                    KeyValueRow(label = "Body hash", value = request.bodyHash, monospace = true)
                    request.headers.toSortedMap().forEach { (name, value) ->
                        KeyValueRow(label = name, value = value, monospace = true)
                    }
                }
            }
            item {
                SectionCard(title = "Canonical body") {
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

private fun signingStateSummary(status: SigningStatus): StatusCalloutState {
    return when (status) {
        SigningStatus.Idle -> StatusCalloutState(
            title = "No request signed yet",
            body = "Generate a demo request to inspect the canonical payload, hash, and signature headers.",
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

package id.fatarc.trustgate.ui.signing

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.ui.KeyValueRow
import id.fatarc.trustgate.ui.SectionCard
import id.fatarc.trustgate.ui.TrustGateUiState

@Composable
fun RequestSigningScreen(
    uiState: TrustGateUiState,
    onSignDemoRequest: () -> Unit,
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            SectionCard(
                title = "Signing shape",
                modifier = Modifier.padding(top = 16.dp),
            ) {
                Text(
                    text = "The app signs a fake payment request with a demo-only local HMAC key. This shows canonicalization and header shape, not production key management.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Button(
                    onClick = onSignDemoRequest,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Sign demo request")
                }
                Text(uiState.signingMessage, style = MaterialTheme.typography.bodyMedium)
            }
        }

        uiState.signedRequest?.let { request ->
            item {
                SectionCard(title = "Signed request") {
                    KeyValueRow(label = "Amount", value = request.payload.amountMinor.toString())
                    KeyValueRow(label = "Currency", value = request.payload.currency)
                    KeyValueRow(label = "Reference", value = request.payload.merchantReference)
                    KeyValueRow(label = "Timestamp", value = request.timestamp, monospace = true)
                    KeyValueRow(label = "Nonce", value = request.nonce, monospace = true)
                    KeyValueRow(label = "Body hash", value = request.bodyHash, monospace = true)
                    request.headers.forEach { (name, value) ->
                        KeyValueRow(label = name, value = value, monospace = true)
                    }
                }
            }
            item {
                SectionCard(
                    title = "Canonical body",
                    modifier = Modifier.padding(bottom = 24.dp),
                ) {
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


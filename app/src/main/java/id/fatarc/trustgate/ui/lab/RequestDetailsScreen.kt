package id.fatarc.trustgate.ui.lab

import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.domain.signing.SignedRequest
import id.fatarc.trustgate.ui.CodeTextStyle
import id.fatarc.trustgate.ui.CopyButton
import id.fatarc.trustgate.ui.RowDivider
import id.fatarc.trustgate.ui.ScreenScaffold
import id.fatarc.trustgate.ui.Section
import id.fatarc.trustgate.ui.SensitiveScreen
import id.fatarc.trustgate.ui.ValueRow

/** The last signed request as it went over the wire, for anyone who wants to see what the server checks. */
@Composable
fun RequestDetailsScreen(
    request: SignedRequest?,
    onNavigateUp: () -> Unit,
) {
    SensitiveScreen()
    ScreenScaffold(title = "What was sent", onNavigateUp = onNavigateUp) {
        if (request == null) {
            item(key = "empty") {
                Text("Nothing has been sent yet.", style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(horizontal = 4.dp))
            }
            return@ScreenScaffold
        }

        item(key = "intro") {
            Text(
                text = "Signed with this phone's key. Change any field and the server refuses it.",
                modifier = Modifier.padding(horizontal = 4.dp),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        item(key = "request") {
            Section(title = "Request") {
                ValueRow(label = "Sent to", value = "${request.method} ${request.path}", monospace = true)
                RowDivider()
                ValueRow(label = "Signed by", value = request.keyId, monospace = true)
                RowDivider()
                ValueRow(label = "Signed at", value = request.timestamp, monospace = true)
                RowDivider()
                ValueRow(label = "Server's one-time code", value = request.nonce, monospace = true, copyable = true)
                request.idempotencyKey?.let {
                    RowDivider()
                    ValueRow(label = "Charge-once key", value = it, monospace = true, copyable = true)
                }
            }
        }

        item(key = "body") {
            Section(title = "Body", action = { CopyButton(label = "Body", value = request.canonicalBody) }) {
                SelectionContainer {
                    Text(text = request.canonicalBody, modifier = Modifier.padding(16.dp), style = CodeTextStyle)
                }
            }
        }

        item(key = "signature") {
            Section(title = "Signature") {
                ValueRow(label = "Body fingerprint (SHA-256)", value = request.bodyHash, monospace = true, copyable = true)
                RowDivider()
                ValueRow(label = "Signature", value = request.signature, monospace = true, copyable = true)
            }
        }
    }
}

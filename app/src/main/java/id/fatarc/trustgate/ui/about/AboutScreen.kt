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

@Composable
fun AboutScreen(
    onNavigateUp: () -> Unit,
) {
    ScreenScaffold(
        title = "About",
        onNavigateUp = onNavigateUp,
    ) {
        item(key = "intro") {
            Text(
                text = "A demo payment app that checks whether a phone is safe to pay from, while the server makes the call.",
                modifier = Modifier.padding(horizontal = 4.dp),
                style = MaterialTheme.typography.bodyLarge,
            )
        }

        item(key = "how") {
            Section(title = "How a payment is protected") {
                Spacer(Modifier.height(6.dp))
                BulletItem("The phone checks itself for root, emulators, debuggers, and where the app came from.")
                BulletItem("It signs that report with a key locked in its hardware.")
                BulletItem("The server scores the report and can ask Google Play Integrity whether the app is genuine.")
                BulletItem("The server then lets the payment through, asks you to confirm, or blocks it.")
                BulletItem("Each request is signed, works once, and charges once.")
                Spacer(Modifier.height(6.dp))
            }
        }

        item(key = "limits") {
            Section(title = "What it can't do") {
                Spacer(Modifier.height(6.dp))
                BulletItem("A phone an attacker fully controls can still lie about itself. The server's checks make that harder, not impossible.")
                BulletItem("No real money moves.")
                Spacer(Modifier.height(6.dp))
            }
        }

        item(key = "server") {
            Section(
                title = "Server",
                footer = "Version ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})",
            ) {
                Text(
                    text = when {
                        BuildConfig.SERVER_URL.isBlank() -> "No server set up in this build."
                        BuildConfig.SERVER_PINNED -> "${BuildConfig.SERVER_URL} over HTTPS. Only the server's own key is accepted."
                        else -> "${BuildConfig.SERVER_URL} over HTTPS."
                    },
                    modifier = Modifier.padding(16.dp),
                    style = MaterialTheme.typography.bodyLarge,
                )
            }
        }
    }
}

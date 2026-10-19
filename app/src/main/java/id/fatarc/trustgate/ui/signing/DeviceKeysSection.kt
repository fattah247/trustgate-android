package id.fatarc.trustgate.ui.signing

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.core.keys.RegisteredKey
import id.fatarc.trustgate.domain.api.AttestationSummary
import id.fatarc.trustgate.domain.api.VerifiedBootState
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.ui.KeysUiState
import id.fatarc.trustgate.ui.ListRow
import id.fatarc.trustgate.ui.RowDivider
import id.fatarc.trustgate.ui.Section
import id.fatarc.trustgate.ui.Tone
import id.fatarc.trustgate.ui.TrustGateSpacing
import id.fatarc.trustgate.ui.contentColor

/** Where each device key lives and what its attestation proved to the backend. */
@Composable
fun DeviceKeysSection(keys: KeysUiState) {
    Section(
        title = "Device keys",
        footer = "Each key's attestation is a certificate chain from Keystore. The reference backend checks it " +
            "certifies this key and its one-time challenge; production also pins Google's attestation roots " +
            "and checks their revocation list.",
    ) {
        val registered = keys.keys
        when {
            registered != null -> {
                KeyRow(
                    key = registered.device,
                    purpose = "Signs ordinary requests.",
                )
                RowDivider(startIndent = TrustGateSpacing.listIconInset)
                val stepUp = registered.stepUp
                if (stepUp != null) {
                    KeyRow(
                        key = stepUp,
                        purpose = if (stepUp.attestation.userAuthRequired == true) {
                            "Signs only after biometrics or the screen lock; the attestation proves it."
                        } else {
                            "Signs only after biometrics or the screen lock."
                        },
                    )
                } else {
                    ListRow(
                        headline = KeyRole.STEP_UP.title(),
                        supporting = registered.stepUpUnavailableReason ?: "Not set up.",
                        supportingColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        leadingIcon = KeyRole.STEP_UP.icon(),
                        trailing = { Trailing("Not set up") },
                    )
                }
            }

            keys.errorMessage != null -> ListRow(
                headline = "Device key unavailable",
                supporting = keys.errorMessage,
                supportingColor = MaterialTheme.colorScheme.onSurfaceVariant,
                leadingIcon = Icons.Outlined.ErrorOutline,
                leadingTint = Tone.CRITICAL.contentColor(),
            )

            else -> Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 3.dp)
                Text("Generating and registering keys…", style = MaterialTheme.typography.bodyLarge)
            }
        }
    }
}

@Composable
private fun KeyRow(
    key: RegisteredKey,
    purpose: String,
) {
    ListRow(
        headline = key.role.title(),
        supporting = "$purpose ${key.attestation.summary()}\n${key.keyId}",
        supportingColor = MaterialTheme.colorScheme.onSurfaceVariant,
        leadingIcon = key.role.icon(),
        leadingTint = if (key.attestation.verified) Tone.POSITIVE.contentColor() else Tone.CAUTION.contentColor(),
        trailing = { Trailing(key.protection.label()) },
    )
}

@Composable
private fun Trailing(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

private fun AttestationSummary.summary(): String {
    if (!attested) return "This device didn't attest the key."
    // The backend refuses attestations that don't verify, so a registered key's always does.
    if (!verified) return "The attestation didn't fully verify."
    return buildString {
        append("Attestation verified (")
        append(chainLength)
        append(" certificates")
        securityLevel?.let { append(", ").append(it.label().lowercase()) }
        append(")")
        verifiedBootState?.let { state ->
            append(", boot ")
            append(
                when (state) {
                    VerifiedBootState.VERIFIED -> "verified"
                    VerifiedBootState.SELF_SIGNED -> "self-signed"
                    VerifiedBootState.UNVERIFIED -> "unverified"
                    VerifiedBootState.FAILED -> "failed"
                },
            )
        }
        deviceLocked?.let { append(if (it) ", bootloader locked" else ", bootloader unlocked") }
        append(".")
    }
}

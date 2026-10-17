package id.fatarc.trustgate.ui.signing

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.core.attestation.AttestationReport
import id.fatarc.trustgate.core.attestation.SecurityLevel
import id.fatarc.trustgate.core.attestation.VerifiedBootState
import id.fatarc.trustgate.core.keys.RegisteredKey
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
                        purpose = if (stepUp.attestation.description?.userAuthRequired == true) {
                            "Signs only after biometrics or the screen lock; the attestation proves it."
                        } else {
                            "Signs only after biometrics or the screen lock."
                        },
                    )
                } else {
                    ListRow(
                        headline = "Step-up key",
                        supporting = registered.stepUpUnavailableReason ?: "Not set up.",
                        supportingColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        leadingIcon = Icons.Outlined.Fingerprint,
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
        leadingTint = if (key.attestation.isVerified) Tone.POSITIVE.contentColor() else Tone.CAUTION.contentColor(),
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

fun KeyRole.title(): String = when (this) {
    KeyRole.DEVICE -> "Device key"
    KeyRole.STEP_UP -> "Step-up key"
}

fun KeyRole.icon(): ImageVector = when (this) {
    KeyRole.DEVICE -> Icons.Outlined.Key
    KeyRole.STEP_UP -> Icons.Outlined.Fingerprint
}

fun SecurityLevel.label(): String = when (this) {
    SecurityLevel.STRONGBOX -> "StrongBox"
    SecurityLevel.TRUSTED_ENVIRONMENT -> "Secure hardware"
    SecurityLevel.SOFTWARE -> "Software"
    SecurityLevel.UNKNOWN -> "Unknown"
}

private fun AttestationReport.summary(): String {
    val description = description ?: return "This device didn't attest the key."
    if (!isVerified) {
        val problem = when {
            !chainSignaturesValid -> "its certificate chain doesn't verify"
            !leafMatchesKey -> "it certifies another key"
            else -> "it was made for another challenge"
        }
        return "The attestation didn't verify: $problem."
    }
    return buildString {
        append("Attestation verified (")
        append(chainLength)
        append(" certificates, ")
        append(description.attestationSecurityLevel.label().lowercase())
        append(")")
        description.rootOfTrust?.let { root ->
            append(", boot ")
            append(
                when (root.verifiedBootState) {
                    VerifiedBootState.VERIFIED -> "verified"
                    VerifiedBootState.SELF_SIGNED -> "self-signed"
                    VerifiedBootState.UNVERIFIED -> "unverified"
                    VerifiedBootState.FAILED -> "failed"
                },
            )
            append(if (root.deviceLocked) ", bootloader locked" else ", bootloader unlocked")
        }
        append(".")
    }
}

package id.fatarc.trustgate.ui.signing

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Key
import androidx.compose.ui.graphics.vector.ImageVector
import id.fatarc.trustgate.domain.api.SecurityLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.RejectionReason

// How keys and server refusals are named wherever they appear, from the Lab to the activity log.

fun KeyRole.title(): String = when (this) {
    KeyRole.DEVICE -> "Phone key"
    KeyRole.STEP_UP -> "Screen-lock key"
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

fun RejectionReason.shortLabel(): String = when (this) {
    RejectionReason.MISSING_HEADERS -> "parts missing"
    RejectionReason.MALFORMED_TIMESTAMP -> "bad time"
    RejectionReason.OUTSIDE_TIME_WINDOW -> "too late"
    RejectionReason.UNKNOWN_KEY -> "unknown phone"
    RejectionReason.SIGNATURE_MISMATCH -> "changed after signing"
    RejectionReason.UNKNOWN_CHALLENGE -> "unknown one-time code"
    RejectionReason.CHALLENGE_REUSED -> "already used"
    RejectionReason.CONFIRMATION_REQUIRED -> "not confirmed"
    RejectionReason.IDEMPOTENCY_CONFLICT -> "charge-once key reused"
    RejectionReason.MALFORMED_BODY -> "unreadable"
}

package id.fatarc.trustgate.ui.events

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Autorenew
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material.icons.outlined.Cancel
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Flag
import androidx.compose.material.icons.outlined.GppBad
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Payments
import androidx.compose.material.icons.outlined.PendingActions
import androidx.compose.material.icons.outlined.PhonelinkErase
import androidx.compose.material.icons.outlined.Radar
import androidx.compose.material.icons.outlined.Science
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.ui.graphics.vector.ImageVector
import id.fatarc.trustgate.core.security.TrustGateSecurityService
import id.fatarc.trustgate.domain.api.SecurityLevel
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.domain.events.SecurityEventType
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.RejectionReason
import id.fatarc.trustgate.ui.Tone
import id.fatarc.trustgate.ui.label
import id.fatarc.trustgate.ui.signing.icon
import id.fatarc.trustgate.ui.signing.label
import id.fatarc.trustgate.ui.signing.shortLabel
import id.fatarc.trustgate.ui.signing.title

enum class EventFilter(val label: String) {
    ALL("All"),
    CHECKS("Checks"),
    PAYMENTS("Payments"),
    LAB("Lab"),
}

fun SecurityEvent.matches(filter: EventFilter): Boolean = filter == EventFilter.ALL || group() == filter

val SecurityEvent.isScenario: Boolean
    get() = metadata["source"] == TrustGateSecurityService.SCENARIO_SOURCE

val SecurityEvent.isRejectedVerification: Boolean
    get() = type == SecurityEventType.REQUEST_VERIFIED && metadata["result"] == "rejected"

private val SecurityEvent.paymentResult: String?
    get() = metadata["result"].takeIf { type == SecurityEventType.PAYMENT_SUBMITTED }

/**
 * Entries that only add detail to another one: each problem a check found, and the signing step
 * before a request is sent. Summaries such as Home's recent list leave them out.
 */
val SecurityEvent.isDetail: Boolean
    get() = type == SecurityEventType.ROOT_SIGNAL_FOUND ||
        type == SecurityEventType.EMULATOR_SIGNAL_FOUND ||
        type == SecurityEventType.DEBUGGER_ATTACHED ||
        type == SecurityEventType.REQUEST_SIGNED

fun SecurityEvent.headline(): String = when (type) {
    SecurityEventType.DEVICE_RISK_ASSESSED -> when {
        isScenario -> "Demo phone chosen"
        metadata["trigger"] == "resume" ->
            if (metadata["previousLevel"] != null && metadata["previousLevel"] != riskLevel?.name) "Phone status changed" else "Problems changed"
        metadata["trigger"] == "before-action" -> "Checked before paying"
        else -> "Phone checked"
    }
    SecurityEventType.ROOT_SIGNAL_FOUND,
    SecurityEventType.EMULATOR_SIGNAL_FOUND,
    // Recorded for every debugging-category signal, including the debuggable build flag.
    SecurityEventType.DEBUGGER_ATTACHED,
    -> "Problem found"
    SecurityEventType.SENSITIVE_ACTION_ALLOWED -> "Payment approved"
    SecurityEventType.SENSITIVE_ACTION_REQUIRES_CONFIRMATION -> "Asked you to confirm"
    SecurityEventType.SENSITIVE_ACTION_ALLOWED_AFTER_CONFIRMATION -> "You confirmed"
    SecurityEventType.SENSITIVE_ACTION_CANCELLED -> "Payment cancelled"
    SecurityEventType.SENSITIVE_ACTION_BLOCKED -> "Payment blocked"
    SecurityEventType.REQUEST_SIGNED -> "Request signed"
    SecurityEventType.REQUEST_VERIFIED -> if (isRejectedVerification) "Attack stopped" else "Request accepted"
    SecurityEventType.SECURE_VALUE_STORED -> "Test values saved"
    SecurityEventType.KEY_REGISTERED -> "${role().title()} set up"
    SecurityEventType.PAYMENT_SUBMITTED -> when (paymentResult) {
        "accepted" -> if (metadata["lostResponses"] != null) "Paid once after a retry" else "Paid"
        "unknown" -> "No answer from the server"
        else -> "Payment refused"
    }
    SecurityEventType.KEY_ROTATED -> "Phone key replaced"
    SecurityEventType.PHONE_REMOVED -> "Phone set up again"
}

fun SecurityEvent.tone(): Tone = when (type) {
    SecurityEventType.DEVICE_RISK_ASSESSED -> when (riskLevel) {
        DeviceRiskLevel.MEDIUM -> Tone.CAUTION
        DeviceRiskLevel.HIGH -> Tone.CRITICAL
        DeviceRiskLevel.LOW, null -> Tone.NEUTRAL
    }

    SecurityEventType.ROOT_SIGNAL_FOUND,
    SecurityEventType.EMULATOR_SIGNAL_FOUND,
    SecurityEventType.DEBUGGER_ATTACHED,
    -> if (riskLevel == DeviceRiskLevel.HIGH) Tone.CRITICAL else Tone.CAUTION

    SecurityEventType.SENSITIVE_ACTION_ALLOWED,
    SecurityEventType.SENSITIVE_ACTION_ALLOWED_AFTER_CONFIRMATION,
    -> Tone.POSITIVE

    SecurityEventType.SENSITIVE_ACTION_REQUIRES_CONFIRMATION -> Tone.CAUTION
    SecurityEventType.SENSITIVE_ACTION_BLOCKED -> Tone.CRITICAL

    // Requests are only checked from the Lab, where a refusal means the server stopped the attack.
    SecurityEventType.REQUEST_VERIFIED -> if (isRejectedVerification) Tone.POSITIVE else Tone.NEUTRAL
    SecurityEventType.KEY_REGISTERED -> if (metadata["attestation"] == "verified") Tone.POSITIVE else Tone.CAUTION
    SecurityEventType.PAYMENT_SUBMITTED -> when (paymentResult) {
        "accepted" -> Tone.POSITIVE
        "unknown" -> Tone.CAUTION
        else -> Tone.CRITICAL
    }

    SecurityEventType.KEY_ROTATED -> Tone.POSITIVE
    SecurityEventType.PHONE_REMOVED -> if (metadata["decidedBy"] == "reference-backend") Tone.CAUTION else Tone.NEUTRAL

    SecurityEventType.SENSITIVE_ACTION_CANCELLED,
    SecurityEventType.REQUEST_SIGNED,
    SecurityEventType.SECURE_VALUE_STORED,
    -> Tone.NEUTRAL
}

val SecurityEvent.icon: ImageVector
    get() = when (type) {
        SecurityEventType.DEVICE_RISK_ASSESSED -> if (isScenario) Icons.Outlined.Science else Icons.Outlined.Radar
        SecurityEventType.ROOT_SIGNAL_FOUND,
        SecurityEventType.EMULATOR_SIGNAL_FOUND,
        SecurityEventType.DEBUGGER_ATTACHED,
        -> Icons.Outlined.Flag

        SecurityEventType.SENSITIVE_ACTION_ALLOWED,
        SecurityEventType.SENSITIVE_ACTION_ALLOWED_AFTER_CONFIRMATION,
        -> Icons.Outlined.CheckCircle

        SecurityEventType.SENSITIVE_ACTION_REQUIRES_CONFIRMATION -> Icons.Outlined.PendingActions
        SecurityEventType.SENSITIVE_ACTION_CANCELLED -> Icons.Outlined.Cancel
        SecurityEventType.SENSITIVE_ACTION_BLOCKED -> Icons.Outlined.Block
        SecurityEventType.REQUEST_SIGNED -> Icons.Outlined.Key
        SecurityEventType.REQUEST_VERIFIED -> if (isRejectedVerification) Icons.Outlined.VerifiedUser else Icons.Outlined.CheckCircle
        SecurityEventType.SECURE_VALUE_STORED -> Icons.Outlined.Lock
        SecurityEventType.KEY_REGISTERED -> role().icon()
        SecurityEventType.PAYMENT_SUBMITTED -> when (paymentResult) {
            "accepted" -> Icons.Outlined.Payments
            "unknown" -> Icons.Outlined.PendingActions
            else -> Icons.Outlined.GppBad
        }
        SecurityEventType.KEY_ROTATED -> Icons.Outlined.Autorenew
        SecurityEventType.PHONE_REMOVED -> Icons.Outlined.PhonelinkErase
    }

fun metadataLabel(key: String): String = when (key) {
    "score" -> "Risk points"
    "signalId" -> "Check"
    "source" -> "Source"
    "nonce" -> "One-time code"
    "signaturePrefix" -> "Signature starts"
    "keys" -> "Saved"
    "trigger" -> "Why"
    "previousLevel" -> "Before"
    "method" -> "Confirmed with"
    "attempt" -> "Sent"
    "result" -> "Result"
    "reason" -> "Reason"
    "decidedBy" -> "Decided by"
    "reasons" -> "What the server saw"
    "keyId" -> "Key ID"
    "role" -> "Key"
    "protection" -> "Stored in"
    "attestation" -> "Proven by Keystore"
    "verifiedBoot" -> "Boot"
    "bootloaderLocked" -> "Bootloader"
    "idempotencyKey" -> "Charge-once key"
    "attempts" -> "Tries"
    "lostResponses" -> "Lost replies"
    "paymentId" -> "Payment"
    else -> key
        .replace(Regex("([a-z])([A-Z])"), "$1 $2")
        .replace('_', ' ')
        .lowercase()
        .replaceFirstChar { it.titlecase() }
}

fun metadataValue(key: String, value: String): String = when {
    key == "source" && value == TrustGateSecurityService.SCENARIO_SOURCE -> "Demo phone"
    key == "keys" -> value.split(',').joinToString(", ")
    key == "trigger" -> when (value) {
        "launch" -> "App opened"
        "manual" -> "You asked"
        "before-action" -> "Before paying"
        "resume" -> "Back in the app"
        else -> value
    }
    key == "previousLevel" -> DeviceRiskLevel.entries.byMetadata(value.lowercase())?.label() ?: value
    key == "method" -> when (value) {
        "device-credential" -> "Screen lock"
        "tap" -> "A tap (no screen lock set)"
        else -> value
    }
    key == "attempt" -> when (value) {
        "as-signed" -> "Unchanged"
        "replay" -> "A second time"
        "changed-amount" -> "With the amount changed"
        "delivered-late" -> "Too late"
        "protected-action" -> "With a payment"
        else -> value
    }
    key == "reason" -> (RejectionReason.entries.byMetadata(value)?.shortLabel() ?: value.replace('_', ' '))
        .replaceFirstChar { it.titlecase() }
    key == "decidedBy" -> when (value) {
        "reference-backend" -> "Server"
        "app" -> "This app"
        else -> value
    }
    key == "role" -> KeyRole.entries.byMetadata(value)?.title() ?: value
    key == "protection" -> SecurityLevel.entries.byMetadata(value)?.label() ?: value.replaceFirstChar { it.titlecase() }
    key == "attestation" -> when (value) {
        "verified" -> "Yes"
        "unverified" -> "Didn't check out"
        "none" -> "No"
        else -> value
    }
    key == "verifiedBoot" -> if (value == "verified") "Verified" else value.replace('_', ' ').replaceFirstChar { it.titlecase() }
    key == "bootloaderLocked" -> if (value == "true") "Locked" else "Unlocked"
    key == "result" -> value.replaceFirstChar { it.titlecase() }
    else -> value
}

private fun SecurityEvent.group(): EventFilter = when (type) {
    SecurityEventType.DEVICE_RISK_ASSESSED,
    SecurityEventType.ROOT_SIGNAL_FOUND,
    SecurityEventType.EMULATOR_SIGNAL_FOUND,
    SecurityEventType.DEBUGGER_ATTACHED,
    -> EventFilter.CHECKS

    SecurityEventType.SENSITIVE_ACTION_ALLOWED,
    SecurityEventType.SENSITIVE_ACTION_REQUIRES_CONFIRMATION,
    SecurityEventType.SENSITIVE_ACTION_ALLOWED_AFTER_CONFIRMATION,
    SecurityEventType.SENSITIVE_ACTION_CANCELLED,
    SecurityEventType.SENSITIVE_ACTION_BLOCKED,
    SecurityEventType.PAYMENT_SUBMITTED,
    -> EventFilter.PAYMENTS

    SecurityEventType.REQUEST_SIGNED,
    SecurityEventType.REQUEST_VERIFIED,
    SecurityEventType.KEY_REGISTERED,
    SecurityEventType.SECURE_VALUE_STORED,
    SecurityEventType.KEY_ROTATED,
    SecurityEventType.PHONE_REMOVED,
    -> EventFilter.LAB
}

/** Metadata holds enum names in lower case; an entry from an older build may name one this build lacks. */
private fun <T : Enum<T>> List<T>.byMetadata(value: String): T? = firstOrNull { it.name.lowercase() == value }

private fun SecurityEvent.role(): KeyRole = KeyRole.entries.byMetadata(metadata["role"].orEmpty()) ?: KeyRole.DEVICE

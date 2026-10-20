package id.fatarc.trustgate.core.security

import id.fatarc.trustgate.core.backend.SubmitOutcome
import id.fatarc.trustgate.core.keys.RegisteredKey
import id.fatarc.trustgate.domain.actiongate.SensitiveActionDecision
import id.fatarc.trustgate.domain.api.DecisionReason
import id.fatarc.trustgate.domain.api.PaymentResponse
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.domain.events.SecurityEventRepository
import id.fatarc.trustgate.domain.events.SecurityEventType
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.DeviceRiskReport
import id.fatarc.trustgate.domain.risk.DeviceSignalCollector
import id.fatarc.trustgate.domain.risk.RiskScorer
import id.fatarc.trustgate.domain.risk.SignalCategory
import id.fatarc.trustgate.domain.risk.flaggedSignalIds
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.RejectionReason
import id.fatarc.trustgate.domain.signing.SignedRequest
import id.fatarc.trustgate.domain.signing.VerificationResult

/** Why a device check ran. It decides how much of the result is worth writing to the capped log. */
enum class AssessmentTrigger(val metadataValue: String) {
    LAUNCH("launch"),
    MANUAL("manual"),

    /** Re-check right before a protected action; logs the check but not every signal again. */
    BEFORE_ACTION("before-action"),

    /** Quiet re-check when the app returns to the foreground; logs only if something changed. */
    RESUME("resume"),
}

enum class ConfirmationMethod(val metadataValue: String) {
    /** Biometric or screen lock through the system prompt. */
    DEVICE_CREDENTIAL("device-credential"),

    /** Explicit tap, used only when the device has no screen lock to step up to. */
    TAP("tap"),
}

class TrustGateSecurityService(
    private val signalCollector: DeviceSignalCollector,
    private val riskScorer: RiskScorer,
    private val eventRepository: SecurityEventRepository,
) {
    suspend fun assessDeviceRisk(
        trigger: AssessmentTrigger = AssessmentTrigger.MANUAL,
        previous: DeviceRiskReport? = null,
    ): DeviceRiskReport {
        val report = riskScorer.score(signalCollector.collectSignals())
        val found = problemsFound(report.signals.count { it.detected })
        when (trigger) {
            AssessmentTrigger.LAUNCH,
            AssessmentTrigger.MANUAL,
            -> {
                recordAssessment(report, trigger, found)
                recordDetectedSignals(report)
            }

            AssessmentTrigger.BEFORE_ACTION -> recordAssessment(
                report = report,
                trigger = trigger,
                message = "Checked again before paying. $found",
            )

            AssessmentTrigger.RESUME -> if (previous == null || report.differsFrom(previous)) {
                val message = if (previous != null && previous.level != report.level) {
                    "Went from ${previous.level.name.lowercase()} to ${report.level.name.lowercase()} risk while you were away."
                } else {
                    "Changed while you were away. $found"
                }
                recordAssessment(
                    report = report,
                    trigger = trigger,
                    message = message,
                    extra = previous?.let { mapOf("previousLevel" to it.level.name) }.orEmpty(),
                )
                recordDetectedSignals(report)
            }
        }
        return report
    }

    /** Logs the gate decision the backend made, at the risk level it assessed, and why. */
    suspend fun recordGateDecision(level: DeviceRiskLevel, decision: SensitiveActionDecision, reasons: List<DecisionReason>) {
        eventRepository.record(
            SecurityEvent(
                type = decision.toSecurityEventType(),
                riskLevel = level,
                message = decision.toAuditMessage(),
                metadata = buildMap {
                    put("decidedBy", "reference-backend")
                    if (reasons.isNotEmpty()) put("reasons", reasons.joinToString("; ") { it.text })
                },
            ),
        )
    }

    /** The device turned high risk while the person was confirming, so the app stopped before signing. */
    suspend fun recordBlockedAfterConfirmation(report: DeviceRiskReport) {
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.SENSITIVE_ACTION_BLOCKED,
                riskLevel = report.level,
                message = "Stopped: the phone turned high risk while you were confirming.",
                metadata = mapOf("decidedBy" to "app"),
            ),
        )
    }

    suspend fun recordKeyRegistered(key: RegisteredKey) {
        val attestation = key.attestation
        val (status, summary) = when {
            attestation.verified -> "verified" to "Keystore vouched for it."
            attestation.attested -> "unverified" to "Keystore's proof didn't check out."
            else -> "none" to "No proof from Keystore."
        }
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.KEY_REGISTERED,
                message = when (key.role) {
                    KeyRole.DEVICE -> "Signs every payment. $summary"
                    KeyRole.STEP_UP -> "Signs only after your screen lock. $summary"
                },
                metadata = buildMap {
                    put("keyId", key.keyId)
                    put("role", key.role.name.lowercase())
                    put("protection", key.protection.name.lowercase())
                    put("attestation", status)
                    attestation.verifiedBootState?.let { put("verifiedBoot", it.name.lowercase()) }
                    attestation.deviceLocked?.let { put("bootloaderLocked", it.toString()) }
                },
            ),
        )
    }

    suspend fun recordPayment(request: SignedRequest, outcome: SubmitOutcome) {
        val response = outcome.response
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.PAYMENT_SUBMITTED,
                message = when (response) {
                    null -> "No answer after ${outcome.attempts} tries. Paying again can't charge twice."
                    is PaymentResponse.Rejected -> "Refused because ${response.reason.auditPhrase()}."
                    is PaymentResponse.Processed -> if (outcome.lostResponses > 0) {
                        "A reply was lost and the app tried again. Charged once: ${response.payment.id}."
                    } else {
                        "Charged once: ${response.payment.id}."
                    }
                },
                metadata = buildMap {
                    put("result", if (response is PaymentResponse.Processed) "accepted" else if (response == null) "unknown" else "rejected")
                    request.idempotencyKey?.let { put("idempotencyKey", it) }
                    put("keyId", request.keyId)
                    put("attempts", outcome.attempts.toString())
                    if (outcome.lostResponses > 0) put("lostResponses", outcome.lostResponses.toString())
                    if (response is PaymentResponse.Processed) put("paymentId", response.payment.id)
                    if (response is PaymentResponse.Rejected) put("reason", response.reason.name.lowercase())
                },
            ),
        )
    }

    suspend fun confirmSensitiveAction(report: DeviceRiskReport, method: ConfirmationMethod) {
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.SENSITIVE_ACTION_ALLOWED_AFTER_CONFIRMATION,
                riskLevel = report.level,
                message = when (method) {
                    ConfirmationMethod.DEVICE_CREDENTIAL -> "Confirmed with your screen lock."
                    ConfirmationMethod.TAP -> "Confirmed with a tap, since this phone has no screen lock."
                },
                metadata = mapOf("method" to method.metadataValue),
            ),
        )
    }

    suspend fun cancelSensitiveAction(report: DeviceRiskReport) {
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.SENSITIVE_ACTION_CANCELLED,
                riskLevel = report.level,
                message = "You cancelled when asked to confirm.",
            ),
        )
    }

    suspend fun recordScenarioApplied(report: DeviceRiskReport) {
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.DEVICE_RISK_ASSESSED,
                riskLevel = report.level,
                message = "Showing a ${report.level.demoPhone()} phone. Payments still go to the real server.",
                metadata = mapOf(
                    "score" to report.score.toString(),
                    "source" to SCENARIO_SOURCE,
                ),
            ),
        )
    }

    suspend fun recordSignedRequest(request: SignedRequest, forProtectedAction: Boolean) {
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.REQUEST_SIGNED,
                message = if (forProtectedAction) {
                    "Signed order ${request.payload.merchantReference} with this phone's key."
                } else {
                    "Signed a Lab test request with this phone's key."
                },
                metadata = mapOf(
                    "nonce" to request.nonce,
                    "keyId" to request.keyId,
                    "signaturePrefix" to request.signature.take(12),
                ),
            ),
        )
    }

    /** [attempt] names how the request was sent, for example as signed or deliberately altered. */
    suspend fun recordVerification(request: SignedRequest, result: VerificationResult, attempt: String) {
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.REQUEST_VERIFIED,
                message = when (result) {
                    VerificationResult.Accepted -> "The server accepted it."
                    is VerificationResult.Rejected -> "The server refused it because ${result.reason.auditPhrase()}."
                },
                metadata = buildMap {
                    put("nonce", request.nonce)
                    put("attempt", attempt)
                    put("result", if (result is VerificationResult.Accepted) "accepted" else "rejected")
                    if (result is VerificationResult.Rejected) put("reason", result.reason.name.lowercase())
                },
            ),
        )
    }

    suspend fun recordSecureValueStored(keys: List<String>) {
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.SECURE_VALUE_STORED,
                message = "Saved encrypted, with a key only this app can use.",
                metadata = mapOf("keys" to keys.joinToString(",")),
            ),
        )
    }

    private suspend fun recordAssessment(
        report: DeviceRiskReport,
        trigger: AssessmentTrigger,
        message: String,
        extra: Map<String, String> = emptyMap(),
    ) {
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.DEVICE_RISK_ASSESSED,
                riskLevel = report.level,
                message = message,
                metadata = mapOf(
                    "score" to report.score.toString(),
                    "trigger" to trigger.metadataValue,
                ) + extra,
            ),
        )
    }

    private suspend fun recordDetectedSignals(report: DeviceRiskReport) {
        report.signals.filter { it.detected }.forEach { signal ->
            signal.category.toSecurityEventType()?.let { eventType ->
                eventRepository.record(
                    SecurityEvent(
                        type = eventType,
                        riskLevel = report.level,
                        message = signal.name,
                        metadata = mapOf("signalId" to signal.id),
                    ),
                )
            }
        }
    }

    private fun DeviceRiskReport.differsFrom(other: DeviceRiskReport): Boolean =
        level != other.level || flaggedSignalIds() != other.flaggedSignalIds()

    companion object {
        const val SCENARIO_SOURCE = "scenario-selector"
    }

    private fun SignalCategory.toSecurityEventType(): SecurityEventType? = when (this) {
        SignalCategory.ROOT -> SecurityEventType.ROOT_SIGNAL_FOUND
        SignalCategory.EMULATOR -> SecurityEventType.EMULATOR_SIGNAL_FOUND
        SignalCategory.DEBUGGER -> SecurityEventType.DEBUGGER_ATTACHED
        SignalCategory.INSTALLER, SignalCategory.SCAM -> null
    }

    private fun SensitiveActionDecision.toSecurityEventType(): SecurityEventType = when (this) {
        SensitiveActionDecision.ALLOW -> SecurityEventType.SENSITIVE_ACTION_ALLOWED
        SensitiveActionDecision.REQUIRE_CONFIRMATION -> SecurityEventType.SENSITIVE_ACTION_REQUIRES_CONFIRMATION
        SensitiveActionDecision.BLOCK -> SecurityEventType.SENSITIVE_ACTION_BLOCKED
    }

    private fun SensitiveActionDecision.toAuditMessage(): String = when (this) {
        SensitiveActionDecision.ALLOW -> "The server let the payment through."
        SensitiveActionDecision.REQUIRE_CONFIRMATION -> "The server wants you to confirm first."
        SensitiveActionDecision.BLOCK -> "The server stopped the payment."
    }

    private fun RejectionReason.auditPhrase(): String = when (this) {
        RejectionReason.MISSING_HEADERS -> "parts of it were missing"
        RejectionReason.MALFORMED_TIMESTAMP -> "its time couldn't be read"
        RejectionReason.OUTSIDE_TIME_WINDOW -> "it arrived too late"
        RejectionReason.UNKNOWN_KEY -> "it doesn't know this phone's key"
        RejectionReason.SIGNATURE_MISMATCH -> "it was changed after signing"
        RejectionReason.UNKNOWN_CHALLENGE -> "its one-time code wasn't issued or has expired"
        RejectionReason.CHALLENGE_REUSED -> "its one-time code was already used"
        RejectionReason.CONFIRMATION_REQUIRED -> "you didn't confirm it"
        RejectionReason.IDEMPOTENCY_CONFLICT -> "its charge-once key belongs to a different payment"
        RejectionReason.MALFORMED_BODY -> "it couldn't be read"
    }

    private fun DeviceRiskLevel.demoPhone(): String = when (this) {
        DeviceRiskLevel.LOW -> "safe"
        DeviceRiskLevel.MEDIUM -> "risky"
        DeviceRiskLevel.HIGH -> "compromised"
    }

    private fun problemsFound(count: Int): String = when (count) {
        0 -> "No problems found."
        1 -> "1 problem found."
        else -> "$count problems found."
    }
}

package id.fatarc.trustgate.core.security

import id.fatarc.trustgate.domain.actiongate.SensitiveActionDecision
import id.fatarc.trustgate.domain.actiongate.SensitiveActionGate
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.domain.events.SecurityEventRepository
import id.fatarc.trustgate.domain.events.SecurityEventType
import id.fatarc.trustgate.domain.risk.DeviceRiskReport
import id.fatarc.trustgate.domain.risk.DeviceSignalCollector
import id.fatarc.trustgate.domain.risk.RiskScorer
import id.fatarc.trustgate.domain.risk.SignalCategory
import id.fatarc.trustgate.domain.signing.SignedRequest

class TrustGateSecurityService(
    private val signalCollector: DeviceSignalCollector,
    private val riskScorer: RiskScorer,
    private val actionGate: SensitiveActionGate,
    private val eventRepository: SecurityEventRepository,
) {
    suspend fun assessDeviceRisk(): DeviceRiskReport {
        val report = riskScorer.score(signalCollector.collectSignals())
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.DEVICE_RISK_ASSESSED,
                riskLevel = report.level,
                message = "Device risk assessed with ${report.signals.count { it.detected }} active signals.",
                metadata = mapOf("score" to report.score.toString()),
            ),
        )

        report.signals.filter { it.detected }.forEach { signal ->
            val eventType = when (signal.category) {
                SignalCategory.ROOT -> SecurityEventType.ROOT_SIGNAL_FOUND
                SignalCategory.EMULATOR -> SecurityEventType.EMULATOR_SIGNAL_FOUND
                SignalCategory.DEBUGGER -> SecurityEventType.DEBUGGER_ATTACHED
                SignalCategory.INSTALLER -> null
            }
            if (eventType != null) {
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

        return report
    }

    suspend fun evaluateSensitiveAction(report: DeviceRiskReport): SensitiveActionDecision {
        return when (val decision = actionGate.decide(report.level)) {
            SensitiveActionDecision.ALLOW -> {
                eventRepository.record(
                    SecurityEvent(
                        type = SecurityEventType.SENSITIVE_ACTION_ALLOWED,
                        riskLevel = report.level,
                        message = "Sensitive action allowed for low-risk device state.",
                    ),
                )
                decision
            }

            SensitiveActionDecision.REQUIRE_CONFIRMATION -> {
                eventRepository.record(
                    SecurityEvent(
                        type = SecurityEventType.SENSITIVE_ACTION_REQUIRES_CONFIRMATION,
                        riskLevel = report.level,
                        message = "Sensitive action requires confirmation because of medium-risk signals.",
                    ),
                )
                decision
            }

            SensitiveActionDecision.BLOCK -> {
                eventRepository.record(
                    SecurityEvent(
                        type = SecurityEventType.SENSITIVE_ACTION_BLOCKED,
                        riskLevel = report.level,
                        message = "Sensitive action blocked because the device is high risk.",
                    ),
                )
                decision
            }
        }
    }

    suspend fun confirmSensitiveAction(report: DeviceRiskReport) {
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.SENSITIVE_ACTION_ALLOWED_AFTER_CONFIRMATION,
                riskLevel = report.level,
                message = "Sensitive action allowed after explicit user confirmation.",
            ),
        )
    }

    suspend fun recordSignedRequest(request: SignedRequest) {
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.REQUEST_SIGNED,
                message = "Signed payment-like request for ${request.payload.merchantReference}.",
                metadata = mapOf(
                    "nonce" to request.nonce,
                    "signaturePrefix" to request.signature.take(12),
                ),
            ),
        )
    }

    suspend fun recordSecureValueStored(keys: List<String>) {
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.SECURE_VALUE_STORED,
                message = "Stored demo values in encrypted local storage.",
                metadata = mapOf("keys" to keys.joinToString(",")),
            ),
        )
    }
}


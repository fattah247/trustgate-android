package id.fatarc.trustgate.domain.actiongate

import id.fatarc.trustgate.domain.risk.DeviceRiskLevel

enum class SensitiveActionDecision {
    ALLOW,
    REQUIRE_CONFIRMATION,
    BLOCK,
}

class SensitiveActionGate {
    fun decide(riskLevel: DeviceRiskLevel): SensitiveActionDecision {
        return when (riskLevel) {
            DeviceRiskLevel.LOW -> SensitiveActionDecision.ALLOW
            DeviceRiskLevel.MEDIUM -> SensitiveActionDecision.REQUIRE_CONFIRMATION
            DeviceRiskLevel.HIGH -> SensitiveActionDecision.BLOCK
        }
    }
}


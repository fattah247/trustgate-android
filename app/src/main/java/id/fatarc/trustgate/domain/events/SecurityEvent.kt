package id.fatarc.trustgate.domain.events

import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import kotlinx.coroutines.flow.StateFlow
import kotlinx.serialization.Serializable
import java.time.Instant

@Serializable
enum class SecurityEventType {
    DEVICE_RISK_ASSESSED,
    ROOT_SIGNAL_FOUND,
    EMULATOR_SIGNAL_FOUND,
    DEBUGGER_ATTACHED,
    SENSITIVE_ACTION_ALLOWED,
    SENSITIVE_ACTION_REQUIRES_CONFIRMATION,
    SENSITIVE_ACTION_ALLOWED_AFTER_CONFIRMATION,
    SENSITIVE_ACTION_BLOCKED,
    REQUEST_SIGNED,
    SECURE_VALUE_STORED,
}

@Serializable
data class SecurityEvent(
    val timestamp: String = Instant.now().toString(),
    val type: SecurityEventType,
    val riskLevel: DeviceRiskLevel? = null,
    val message: String,
    val metadata: Map<String, String> = emptyMap(),
)

interface SecurityEventRepository {
    val events: StateFlow<List<SecurityEvent>>

    suspend fun record(event: SecurityEvent)
}


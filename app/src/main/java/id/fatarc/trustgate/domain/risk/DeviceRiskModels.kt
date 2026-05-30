package id.fatarc.trustgate.domain.risk

import java.time.Instant
import kotlinx.serialization.Serializable

@Serializable
enum class DeviceRiskLevel {
    LOW,
    MEDIUM,
    HIGH,
}

enum class SignalSeverity(val weight: Int) {
    LOW(1),
    MEDIUM(2),
    HIGH(3),
}

enum class SignalCategory {
    ROOT,
    EMULATOR,
    DEBUGGER,
    INSTALLER,
}

data class RiskSignal(
    val id: String,
    val name: String,
    val category: SignalCategory,
    val severity: SignalSeverity,
    val detected: Boolean,
    val explanation: String,
)

data class DeviceRiskReport(
    val signals: List<RiskSignal>,
    val score: Int,
    val level: DeviceRiskLevel,
    val assessedAt: Instant = Instant.now(),
)

interface DeviceSignalCollector {
    fun collectSignals(): List<RiskSignal>
}

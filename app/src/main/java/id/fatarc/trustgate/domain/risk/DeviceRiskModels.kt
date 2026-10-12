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

/** The rule that produced a report's level, so the verdict can be explained instead of just shown. */
sealed interface RiskReason {
    /** At least one high-severity signal forces a high-risk verdict whatever the total. */
    data class SevereSignal(val signalIds: List<String>) : RiskReason

    /** Detected signals added up to [score], reaching [threshold] for the level. */
    data class ScoreThreshold(val score: Int, val threshold: Int) : RiskReason

    /** Nothing reached a threshold; [score] may still be above zero for weak signals. */
    data class BelowThresholds(val score: Int) : RiskReason
}

data class DeviceRiskReport(
    val signals: List<RiskSignal>,
    val score: Int,
    val level: DeviceRiskLevel,
    val reason: RiskReason,
    val assessedAt: Instant = Instant.now(),
)

fun DeviceRiskReport.flaggedSignalIds(): Set<String> =
    signals.filter { it.detected }.mapTo(mutableSetOf()) { it.id }

interface DeviceSignalCollector {
    fun collectSignals(): List<RiskSignal>
}

package id.fatarc.trustgate.domain.risk

import java.time.Clock

class RiskScorer(
    private val clock: Clock = Clock.systemUTC(),
) {
    fun score(signals: List<RiskSignal>): DeviceRiskReport {
        val detectedSignals = signals.filter { it.detected }
        val totalScore = detectedSignals.sumOf { it.severity.weight }
        val hasSevereSignal = detectedSignals.any { it.severity == SignalSeverity.HIGH }
        val level = when {
            hasSevereSignal || totalScore >= 5 -> DeviceRiskLevel.HIGH
            totalScore >= 2 || detectedSignals.size >= 2 -> DeviceRiskLevel.MEDIUM
            else -> DeviceRiskLevel.LOW
        }
        return DeviceRiskReport(
            signals = signals,
            score = totalScore,
            level = level,
            assessedAt = clock.instant(),
        )
    }
}


package id.fatarc.trustgate.domain.risk

import java.time.Clock

class RiskScorer(
    private val clock: Clock = Clock.systemUTC(),
) {
    fun score(signals: List<RiskSignal>): DeviceRiskReport {
        val detectedSignals = signals.filter { it.detected }
        val totalScore = detectedSignals.sumOf { it.severity.weight }
        val severeSignals = detectedSignals.filter { it.severity == SignalSeverity.HIGH }
        // Every severity weighs at least 1, so two or more detected signals always reach the medium threshold.
        val (level, reason) = when {
            severeSignals.isNotEmpty() ->
                DeviceRiskLevel.HIGH to RiskReason.SevereSignal(severeSignals.map { it.id })

            totalScore >= HIGH_SCORE_THRESHOLD ->
                DeviceRiskLevel.HIGH to RiskReason.ScoreThreshold(totalScore, HIGH_SCORE_THRESHOLD)

            totalScore >= MEDIUM_SCORE_THRESHOLD ->
                DeviceRiskLevel.MEDIUM to RiskReason.ScoreThreshold(totalScore, MEDIUM_SCORE_THRESHOLD)

            else -> DeviceRiskLevel.LOW to RiskReason.BelowThresholds(totalScore)
        }
        return DeviceRiskReport(
            signals = signals,
            score = totalScore,
            level = level,
            reason = reason,
            assessedAt = clock.instant(),
        )
    }

    companion object {
        const val MEDIUM_SCORE_THRESHOLD = 2
        const val HIGH_SCORE_THRESHOLD = 5
    }
}

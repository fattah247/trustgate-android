package id.fatarc.trustgate.domain.risk

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.testing.riskSignal
import org.junit.Test

class RiskScorerTest {
    private val scorer = RiskScorer()

    @Test
    fun `risk score maps clean device to low`() {
        val report = scorer.score(
            listOf(
                riskSignal("root", SignalSeverity.HIGH, detected = false),
                riskSignal("emulator", SignalSeverity.MEDIUM, detected = false),
            ),
        )

        assertThat(report.level).isEqualTo(DeviceRiskLevel.LOW)
        assertThat(report.score).isEqualTo(0)
    }

    @Test
    fun `moderate signals are medium risk by score`() {
        val report = scorer.score(
            listOf(
                riskSignal("installer", SignalSeverity.LOW),
                riskSignal("test-keys", SignalSeverity.MEDIUM),
            ),
        )

        assertThat(report.level).isEqualTo(DeviceRiskLevel.MEDIUM)
        assertThat(report.score).isEqualTo(3)
        assertThat(report.reason).isEqualTo(RiskReason.ScoreThreshold(score = 3, threshold = RiskScorer.MEDIUM_SCORE_THRESHOLD))
    }

    @Test
    fun `a severe signal is high risk even when the total is low`() {
        val report = scorer.score(listOf(riskSignal("debugger", SignalSeverity.HIGH)))

        assertThat(report.level).isEqualTo(DeviceRiskLevel.HIGH)
        assertThat(report.score).isEqualTo(3)
        assertThat(report.reason).isEqualTo(RiskReason.SevereSignal(listOf("debugger")))
    }

    @Test
    fun `weaker signals that add up to five are high risk by score`() {
        val report = scorer.score(
            listOf(
                riskSignal("emulator", SignalSeverity.MEDIUM),
                riskSignal("debuggable", SignalSeverity.MEDIUM),
                riskSignal("installer", SignalSeverity.LOW),
            ),
        )

        assertThat(report.level).isEqualTo(DeviceRiskLevel.HIGH)
        assertThat(report.reason).isEqualTo(RiskReason.ScoreThreshold(score = 5, threshold = RiskScorer.HIGH_SCORE_THRESHOLD))
    }

    @Test
    fun `a single weak signal stays low and reports its points`() {
        val report = scorer.score(listOf(riskSignal("installer", SignalSeverity.LOW)))

        assertThat(report.level).isEqualTo(DeviceRiskLevel.LOW)
        assertThat(report.reason).isEqualTo(RiskReason.BelowThresholds(score = 1))
    }
}


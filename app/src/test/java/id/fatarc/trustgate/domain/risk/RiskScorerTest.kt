package id.fatarc.trustgate.domain.risk

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class RiskScorerTest {
    private val scorer = RiskScorer()

    @Test
    fun `risk score maps clean device to low`() {
        val report = scorer.score(
            listOf(
                signal("root", SignalSeverity.HIGH, detected = false),
                signal("emulator", SignalSeverity.MEDIUM, detected = false),
            ),
        )

        assertThat(report.level).isEqualTo(DeviceRiskLevel.LOW)
        assertThat(report.score).isEqualTo(0)
    }

    @Test
    fun `risk score maps moderate signals to medium`() {
        val report = scorer.score(
            listOf(
                signal("installer", SignalSeverity.LOW, detected = true),
                signal("test-keys", SignalSeverity.MEDIUM, detected = true),
            ),
        )

        assertThat(report.level).isEqualTo(DeviceRiskLevel.MEDIUM)
        assertThat(report.score).isEqualTo(3)
    }

    @Test
    fun `risk score maps severe signal to high`() {
        val report = scorer.score(
            listOf(
                signal("debugger", SignalSeverity.HIGH, detected = true),
            ),
        )

        assertThat(report.level).isEqualTo(DeviceRiskLevel.HIGH)
        assertThat(report.score).isEqualTo(3)
    }

    private fun signal(
        id: String,
        severity: SignalSeverity,
        detected: Boolean,
    ): RiskSignal {
        return RiskSignal(
            id = id,
            name = id,
            category = SignalCategory.ROOT,
            severity = severity,
            detected = detected,
            explanation = "test signal",
        )
    }
}


package id.fatarc.trustgate.domain.risk

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class ScenarioRiskReportsTest {
    @Test
    fun `low scenario profile stays low risk`() {
        val report = scenarioRiskReport(DeviceRiskLevel.LOW)

        assertThat(report.level).isEqualTo(DeviceRiskLevel.LOW)
        assertThat(report.signals.any { it.detected }).isFalse()
    }

    @Test
    fun `high scenario profile stays high risk`() {
        val report = scenarioRiskReport(DeviceRiskLevel.HIGH)

        assertThat(report.level).isEqualTo(DeviceRiskLevel.HIGH)
        assertThat(report.signals.count { it.detected }).isAtLeast(1)
        assertThat(report.score).isAtLeast(3)
    }
}

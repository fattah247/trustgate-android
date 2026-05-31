package id.fatarc.trustgate.domain.risk

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class DemoRiskReportsTest {
    @Test
    fun `low demo profile stays low risk`() {
        val report = demoRiskReport(DeviceRiskLevel.LOW)

        assertThat(report.level).isEqualTo(DeviceRiskLevel.LOW)
        assertThat(report.signals.any { it.detected }).isFalse()
    }

    @Test
    fun `high demo profile stays high risk`() {
        val report = demoRiskReport(DeviceRiskLevel.HIGH)

        assertThat(report.level).isEqualTo(DeviceRiskLevel.HIGH)
        assertThat(report.signals.count { it.detected }).isAtLeast(1)
        assertThat(report.score).isAtLeast(3)
    }
}

package id.fatarc.trustgate.domain.risk

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class ScenarioRiskReportsTest {
    @Test
    fun `every scenario profile is scored to the level it simulates`() {
        DeviceRiskLevel.entries.forEach { level ->
            assertThat(scenarioRiskReport(level).level).isEqualTo(level)
        }
    }

    @Test
    fun `low scenario profile has no detected signals`() {
        assertThat(scenarioRiskReport(DeviceRiskLevel.LOW).signals.none { it.detected }).isTrue()
    }

    @Test
    fun `high scenario profile is high because of a severe signal`() {
        assertThat(scenarioRiskReport(DeviceRiskLevel.HIGH).reason).isInstanceOf(RiskReason.SevereSignal::class.java)
    }

    @Test
    fun `simulated signals keep the categories the live checks give them`() {
        val categories = DeviceRiskLevel.entries
            .flatMap { scenarioRiskReport(it).signals }
            .map { it.id to it.category }
            .toSet()

        assertThat(categories).containsExactly(
            "installer_source_unknown" to SignalCategory.INSTALLER,
            "debugger_connected" to SignalCategory.DEBUGGER,
            "test_keys" to SignalCategory.ROOT,
            "root_package" to SignalCategory.ROOT,
        )
    }
}

package id.fatarc.trustgate.domain.actiongate

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import org.junit.Test

class SensitiveActionGateTest {
    private val gate = SensitiveActionGate()

    @Test
    fun `high-risk device blocks sensitive action`() {
        assertThat(gate.decide(DeviceRiskLevel.HIGH)).isEqualTo(SensitiveActionDecision.BLOCK)
    }

    @Test
    fun `medium-risk device requires confirmation`() {
        assertThat(gate.decide(DeviceRiskLevel.MEDIUM)).isEqualTo(SensitiveActionDecision.REQUIRE_CONFIRMATION)
    }

    @Test
    fun `low-risk device allows sensitive action`() {
        assertThat(gate.decide(DeviceRiskLevel.LOW)).isEqualTo(SensitiveActionDecision.ALLOW)
    }
}


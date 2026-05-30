package id.fatarc.trustgate.domain.security

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.core.security.TrustGateSecurityService
import id.fatarc.trustgate.domain.actiongate.SensitiveActionGate
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.domain.events.SecurityEventRepository
import id.fatarc.trustgate.domain.events.SecurityEventType
import id.fatarc.trustgate.domain.risk.DeviceSignalCollector
import id.fatarc.trustgate.domain.risk.RiskScorer
import id.fatarc.trustgate.domain.risk.RiskSignal
import id.fatarc.trustgate.domain.risk.SignalCategory
import id.fatarc.trustgate.domain.risk.SignalSeverity
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.test.runTest
import org.junit.Test

class TrustGateSecurityServiceTest {
    @Test
    fun `security event is created after risk assessment`() = runTest {
        val repository = InMemorySecurityEventRepository()
        val service = TrustGateSecurityService(
            signalCollector = FakeSignalCollector(
                listOf(
                    detectedSignal(
                        id = "root_package",
                        category = SignalCategory.ROOT,
                        severity = SignalSeverity.HIGH,
                    ),
                ),
            ),
            riskScorer = RiskScorer(),
            actionGate = SensitiveActionGate(),
            eventRepository = repository,
        )

        service.assessDeviceRisk()

        assertThat(repository.events.value.map { it.type }).contains(SecurityEventType.DEVICE_RISK_ASSESSED)
        assertThat(repository.events.value.map { it.type }).contains(SecurityEventType.ROOT_SIGNAL_FOUND)
    }

    @Test
    fun `security event is created after blocked action`() = runTest {
        val repository = InMemorySecurityEventRepository()
        val service = TrustGateSecurityService(
            signalCollector = FakeSignalCollector(
                listOf(
                    detectedSignal(
                        id = "debugger_connected",
                        category = SignalCategory.DEBUGGER,
                        severity = SignalSeverity.HIGH,
                    ),
                ),
            ),
            riskScorer = RiskScorer(),
            actionGate = SensitiveActionGate(),
            eventRepository = repository,
        )

        val report = service.assessDeviceRisk()
        service.evaluateSensitiveAction(report)

        assertThat(repository.events.value.last().type).isEqualTo(SecurityEventType.SENSITIVE_ACTION_BLOCKED)
    }

    private fun detectedSignal(
        id: String,
        category: SignalCategory,
        severity: SignalSeverity,
    ): RiskSignal {
        return RiskSignal(
            id = id,
            name = id,
            category = category,
            severity = severity,
            detected = true,
            explanation = "test signal",
        )
    }
}

private class FakeSignalCollector(
    private val signals: List<RiskSignal>,
) : DeviceSignalCollector {
    override fun collectSignals(): List<RiskSignal> = signals
}

private class InMemorySecurityEventRepository : SecurityEventRepository {
    private val state = MutableStateFlow<List<SecurityEvent>>(emptyList())
    override val events: StateFlow<List<SecurityEvent>> = state

    override suspend fun record(event: SecurityEvent) {
        state.value = state.value + event
    }
}


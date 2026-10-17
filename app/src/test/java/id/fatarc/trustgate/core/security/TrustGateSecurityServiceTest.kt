package id.fatarc.trustgate.core.security

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.domain.actiongate.SensitiveActionGate
import id.fatarc.trustgate.domain.events.SecurityEventRepository
import id.fatarc.trustgate.domain.events.SecurityEventType
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.DeviceSignalCollector
import id.fatarc.trustgate.domain.risk.RiskScorer
import id.fatarc.trustgate.domain.risk.RiskSignal
import id.fatarc.trustgate.domain.risk.SignalCategory
import id.fatarc.trustgate.domain.risk.SignalSeverity
import id.fatarc.trustgate.domain.risk.scenarioRiskReport
import id.fatarc.trustgate.domain.signing.PaymentRequestPayload
import id.fatarc.trustgate.domain.signing.ReferenceRequestSigner
import id.fatarc.trustgate.domain.signing.RejectionReason
import id.fatarc.trustgate.domain.signing.VerificationResult
import id.fatarc.trustgate.testing.InMemorySecurityEventRepository
import id.fatarc.trustgate.testing.MutableSignalCollector
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.riskSignal
import kotlinx.coroutines.test.runTest
import org.junit.Test

class TrustGateSecurityServiceTest {
    @Test
    fun `security event is created after risk assessment`() = runTest {
        val repository = InMemorySecurityEventRepository()
        val service = serviceWith(repository, listOf(riskSignal("root_package", SignalSeverity.HIGH, SignalCategory.ROOT)))

        service.assessDeviceRisk()

        assertThat(repository.events.value.map { it.type }).contains(SecurityEventType.DEVICE_RISK_ASSESSED)
        assertThat(repository.events.value.map { it.type }).contains(SecurityEventType.ROOT_SIGNAL_FOUND)
    }

    @Test
    fun `security event is created after blocked action`() = runTest {
        val repository = InMemorySecurityEventRepository()
        val service = serviceWith(repository, listOf(riskSignal("debugger_connected", SignalSeverity.HIGH, SignalCategory.DEBUGGER)))

        val report = service.assessDeviceRisk()
        service.recordGateDecision(report, SensitiveActionGate().decide(report.level))

        assertThat(repository.events.value.last().type).isEqualTo(SecurityEventType.SENSITIVE_ACTION_BLOCKED)
    }

    @Test
    fun `re-check without signal details records only the assessment`() = runTest {
        val repository = InMemorySecurityEventRepository()
        val service = serviceWith(
            repository = repository,
            signals = listOf(
                riskSignal("root_package", SignalSeverity.HIGH, SignalCategory.ROOT),
                riskSignal("debugger_connected", SignalSeverity.HIGH, SignalCategory.DEBUGGER),
            ),
        )

        val report = service.assessDeviceRisk(trigger = AssessmentTrigger.BEFORE_ACTION)

        assertThat(report.level).isEqualTo(DeviceRiskLevel.HIGH)
        assertThat(repository.events.value.map { it.type }).containsExactly(SecurityEventType.DEVICE_RISK_ASSESSED)
    }

    @Test
    fun `resume check stays silent when nothing changed`() = runTest {
        val repository = InMemorySecurityEventRepository()
        val collector = MutableSignalCollector(
            listOf(riskSignal("test_keys", SignalSeverity.MEDIUM, SignalCategory.ROOT)),
        )
        val service = serviceWith(repository = repository, collector = collector)
        val first = service.assessDeviceRisk(trigger = AssessmentTrigger.LAUNCH)
        val eventsAfterLaunch = repository.events.value.size

        service.assessDeviceRisk(trigger = AssessmentTrigger.RESUME, previous = first)

        assertThat(repository.events.value).hasSize(eventsAfterLaunch)
    }

    @Test
    fun `resume check records the change when the verdict moves`() = runTest {
        val repository = InMemorySecurityEventRepository()
        val collector = MutableSignalCollector(
            listOf(riskSignal("test_keys", SignalSeverity.MEDIUM, SignalCategory.ROOT)),
        )
        val service = serviceWith(repository = repository, collector = collector)
        val first = service.assessDeviceRisk(trigger = AssessmentTrigger.LAUNCH)

        collector.signals = collector.signals + riskSignal("debugger_connected", SignalSeverity.HIGH, SignalCategory.DEBUGGER)
        val second = service.assessDeviceRisk(trigger = AssessmentTrigger.RESUME, previous = first)

        val assessment = repository.events.value.last { it.type == SecurityEventType.DEVICE_RISK_ASSESSED }
        assertThat(second.level).isEqualTo(DeviceRiskLevel.HIGH)
        assertThat(assessment.metadata["trigger"]).isEqualTo("resume")
        assertThat(assessment.metadata["previousLevel"]).isEqualTo("MEDIUM")
        assertThat(repository.events.value.last().type).isEqualTo(SecurityEventType.DEBUGGER_ATTACHED)
    }

    @Test
    fun `confirmation records how the person confirmed`() = runTest {
        val repository = InMemorySecurityEventRepository()
        val service = serviceWith(repository = repository, signals = emptyList())
        val report = service.assessDeviceRisk()

        service.confirmSensitiveAction(report, ConfirmationMethod.DEVICE_CREDENTIAL)

        assertThat(repository.events.value.last().metadata["method"]).isEqualTo("device-credential")
    }

    @Test
    fun `verifier rejection is recorded with its reason`() = runTest {
        val repository = InMemorySecurityEventRepository()
        val service = serviceWith(repository = repository, signals = emptyList())
        val request = TestKey().let { key ->
            key.sign(
                ReferenceRequestSigner().prepare(
                    payload = PaymentRequestPayload(amountMinor = 1, currency = "IDR", merchantReference = "REF-1"),
                    nonce = "n-1",
                    keyId = key.keyId,
                    timestamp = "2026-05-31T00:00:00Z",
                ),
            )
        }

        service.recordVerification(request, VerificationResult.Rejected(RejectionReason.CHALLENGE_REUSED), attempt = "as-signed")

        val event = repository.events.value.single()
        assertThat(event.type).isEqualTo(SecurityEventType.REQUEST_VERIFIED)
        assertThat(event.metadata).containsEntry("result", "rejected")
        assertThat(event.metadata).containsEntry("reason", "challenge_reused")
    }

    @Test
    fun `security event is created when a confirmation is cancelled`() = runTest {
        val repository = InMemorySecurityEventRepository()
        val service = serviceWith(
            repository = repository,
            signals = listOf(
                riskSignal("test_keys", SignalSeverity.MEDIUM, SignalCategory.ROOT),
            ),
        )

        val report = service.assessDeviceRisk()
        service.recordGateDecision(report, SensitiveActionGate().decide(report.level))
        service.cancelSensitiveAction(report)

        assertThat(repository.events.value.takeLast(2).map { it.type }).containsExactly(
            SecurityEventType.SENSITIVE_ACTION_REQUIRES_CONFIRMATION,
            SecurityEventType.SENSITIVE_ACTION_CANCELLED,
        ).inOrder()
        assertThat(repository.events.value.last().riskLevel).isEqualTo(DeviceRiskLevel.MEDIUM)
    }

    @Test
    fun `scenario profile is recorded with its source`() = runTest {
        val repository = InMemorySecurityEventRepository()
        val service = serviceWith(repository = repository, signals = emptyList())

        service.recordScenarioApplied(scenarioRiskReport(DeviceRiskLevel.HIGH))

        val event = repository.events.value.single()
        assertThat(event.type).isEqualTo(SecurityEventType.DEVICE_RISK_ASSESSED)
        assertThat(event.riskLevel).isEqualTo(DeviceRiskLevel.HIGH)
        assertThat(event.metadata["source"]).isEqualTo("scenario-selector")
    }

    private fun serviceWith(
        repository: SecurityEventRepository,
        signals: List<RiskSignal> = emptyList(),
        collector: DeviceSignalCollector = MutableSignalCollector(signals),
    ): TrustGateSecurityService = TrustGateSecurityService(
        signalCollector = collector,
        riskScorer = RiskScorer(),
        eventRepository = repository,
    )
}

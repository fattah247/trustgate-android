package id.fatarc.trustgate.backend

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.backend.integrity.IntegrityVerdict
import id.fatarc.trustgate.domain.actiongate.SensitiveActionDecision
import id.fatarc.trustgate.domain.api.DeviceEvidence
import id.fatarc.trustgate.domain.api.MOCK_INTEGRITY_TOKEN_PREFIX
import id.fatarc.trustgate.domain.api.RegistrationResult
import id.fatarc.trustgate.domain.api.ReportedSignal
import id.fatarc.trustgate.domain.api.TrustGateJson
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.SignalCatalog
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.testing.MutableClock
import id.fatarc.trustgate.testing.TEST_PACKAGE
import id.fatarc.trustgate.testing.TEST_SIGNER_DIGEST
import id.fatarc.trustgate.testing.TestAttestation
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.strictBackendPolicy
import id.fatarc.trustgate.testing.developmentPolicy
import id.fatarc.trustgate.testing.selfSignedChain
import org.junit.Test

class PaymentAuthorizationTest {
    private val clock = MutableClock()
    private val device = TestKey()

    private val attestation = TestAttestation()

    private fun backendWith(policy: BackendPolicy) = ReferenceBackend(policy, clock).apply {
        val challenge = issueRegistrationChallenge()
        val chain = if (policy.name == "strict") attestation.chainFor(device.pair.public, challenge) else selfSignedChain(device)
        check(registerKey(KeyRole.DEVICE, device.encodedPublicKey, chain, challenge) is RegistrationResult.Registered)
    }

    private fun evidence(signals: List<ReportedSignal> = emptyList(), simulated: Boolean = false, collectedAt: String = clock.now.toString()) =
        TrustGateJson.encodeToString(DeviceEvidence.serializer(), DeviceEvidence(device.keyId, collectedAt, signals, simulated))

    private fun ReferenceBackend.authorize(evidence: String, token: String? = null, signedBy: TestKey = device) =
        authorizePayment(device.keyId, evidence, signedBy.sign(evidence.toByteArray()), token, clock.now)

    private fun strict(verdict: IntegrityVerdict?) = strictBackendPolicy(attestation, integrity = { verdict })

    private fun genuineVerdict(evidence: String, deviceRecognition: Set<String> = setOf("MEETS_DEVICE_INTEGRITY")) = IntegrityVerdict(
        requestPackageName = TEST_PACKAGE,
        requestHash = ReferenceSigningScheme.sha256Hex(evidence),
        timestampMillis = clock.now.toEpochMilli(),
        appRecognition = "PLAY_RECOGNIZED",
        certificateDigests = setOf(TEST_SIGNER_DIGEST),
        deviceRecognition = deviceRecognition,
    )

    @Test
    fun `evidence signed by another key is refused`() {
        val authorization = backendWith(developmentPolicy).authorize(evidence(), signedBy = TestKey())

        assertThat(authorization.decision).isEqualTo(SensitiveActionDecision.BLOCK)
        assertThat(authorization.reasons.single()).contains("not signed")
    }

    @Test
    fun `evidence older than the time window is refused`() {
        val stale = evidence(collectedAt = clock.now.minus(ReferenceSigningScheme.TIME_WINDOW).minusSeconds(1).toString())

        assertThat(backendWith(developmentPolicy).authorize(stale).reasons.single()).contains("out of date")
    }

    @Test
    fun `the server scores signals from its catalog, not from what the app claims`() {
        // Only ids travel; a tampered app can't report the debugger as a low-severity signal.
        val authorization = backendWith(developmentPolicy).authorize(
            evidence(listOf(ReportedSignal(SignalCatalog.DEBUGGER_CONNECTED.id, detected = true), ReportedSignal("made_up", detected = true))),
        )

        assertThat(authorization.level).isEqualTo(DeviceRiskLevel.HIGH)
    }

    @Test
    fun `a strict server refuses simulated profiles and mock verdicts`() {
        val evidence = evidence(simulated = true)
        val authorization = backendWith(strict(verdict = null)).authorize(evidence, token = MOCK_INTEGRITY_TOKEN_PREFIX + ReferenceSigningScheme.sha256Hex(evidence))

        assertThat(authorization.decision).isEqualTo(SensitiveActionDecision.BLOCK)
        assertThat(authorization.reasons.joinToString()).contains("Demo phones not accepted")
    }

    @Test
    fun `a strict server asks for confirmation when no integrity verdict comes with the request`() {
        assertThat(backendWith(strict(verdict = null)).authorize(evidence()).level).isEqualTo(DeviceRiskLevel.MEDIUM)
    }

    @Test
    fun `a genuine verdict for this exact evidence lets a clean device through`() {
        val evidence = evidence()

        val authorization = backendWith(strict(genuineVerdict(evidence))).authorize(evidence, token = "play-token")

        assertThat(authorization.decision).isEqualTo(SensitiveActionDecision.ALLOW)
    }

    @Test
    fun `a verdict issued for other evidence is refused`() {
        val authorization = backendWith(strict(genuineVerdict(evidence(listOf(ReportedSignal("x", false)))))).authorize(evidence(), token = "play-token")

        assertThat(authorization.reasons.joinToString()).contains("different request")
        assertThat(authorization.level).isEqualTo(DeviceRiskLevel.HIGH)
    }

    @Test
    fun `a device Google Play doesn't vouch for is blocked`() {
        val evidence = evidence()

        val authorization = backendWith(strict(genuineVerdict(evidence, deviceRecognition = emptySet()))).authorize(evidence, token = "play-token")

        assertThat(authorization.decision).isEqualTo(SensitiveActionDecision.BLOCK)
    }

    @Test
    fun `a copy of the app Google Play doesn't recognise is blocked`() {
        val evidence = evidence()
        val unrecognised = genuineVerdict(evidence).copy(appRecognition = "UNRECOGNIZED_VERSION")

        assertThat(backendWith(strict(unrecognised)).authorize(evidence, token = "play-token").decision).isEqualTo(SensitiveActionDecision.BLOCK)
    }

    @Test
    fun `the development policy accepts a mock verdict and says so`() {
        val evidence = evidence()

        val authorization = backendWith(developmentPolicy).authorize(evidence, token = MOCK_INTEGRITY_TOKEN_PREFIX + ReferenceSigningScheme.sha256Hex(evidence))

        assertThat(authorization.decision).isEqualTo(SensitiveActionDecision.ALLOW)
        assertThat(authorization.reasons.joinToString()).contains("test mode")
    }
}

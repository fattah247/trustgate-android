package id.fatarc.trustgate.backend

import id.fatarc.trustgate.testing.TEST_PAYMENT
import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.backend.integrity.IntegrityVerdict
import id.fatarc.trustgate.domain.actiongate.SensitiveActionDecision
import id.fatarc.trustgate.domain.api.DeviceEvidence
import id.fatarc.trustgate.domain.api.MOCK_INTEGRITY_TOKEN_PREFIX
import id.fatarc.trustgate.domain.api.MockIntegrityClaims
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.PlayIntegrityLabels
import id.fatarc.trustgate.domain.api.Remedy
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

    private fun backendWith(policy: BackendPolicy, appVersionCode: Int = 1) = ReferenceBackend(policy, clock).apply {
        val challenge = issueRegistrationChallenge()
        val chain = if (policy.name == "strict") {
            attestation.chainFor(device.pair.public, challenge, appVersionCode = appVersionCode)
        } else {
            selfSignedChain(device)
        }
        check(registerKey(KeyRole.DEVICE, device.encodedPublicKey, chain, challenge) is RegistrationResult.Registered)
    }

    private fun evidence(signals: List<ReportedSignal> = emptyList(), simulated: Boolean = false, collectedAt: String = clock.now.toString()) =
        TrustGateJson.encodeToString(DeviceEvidence.serializer(), DeviceEvidence(device.keyId, collectedAt, signals, simulated, payment = TEST_PAYMENT))

    private fun ReferenceBackend.authorize(evidence: String, token: String? = null, signedBy: TestKey = device) =
        authorizePayment(device.keyId, evidence, signedBy.sign(evidence.toByteArray()), token, clock.now)

    private fun strict(verdict: IntegrityVerdict?, minimumAppVersionCode: Long? = null) =
        strictBackendPolicy(attestation, integrity = { verdict }, minimumAppVersionCode = minimumAppVersionCode)

    private fun genuineVerdict(
        evidence: String,
        deviceRecognition: Set<String> = setOf(PlayIntegrityLabels.MEETS_DEVICE_INTEGRITY, PlayIntegrityLabels.MEETS_STRONG_INTEGRITY),
    ) = IntegrityVerdict(
        requestPackageName = TEST_PACKAGE,
        requestHash = ReferenceSigningScheme.sha256Hex(evidence),
        timestampMillis = clock.now.toEpochMilli(),
        appRecognition = "PLAY_RECOGNIZED",
        certificateDigests = setOf(TEST_SIGNER_DIGEST),
        deviceRecognition = deviceRecognition,
        appVersionCode = 1,
    )

    /** A strict server's answer for clean evidence and a genuine verdict changed by [change]. */
    private fun authorizeWithVerdict(change: (IntegrityVerdict) -> IntegrityVerdict): PaymentAuthorization {
        val evidence = evidence()
        return backendWith(strict(change(genuineVerdict(evidence)), minimumAppVersionCode = 1)).authorize(evidence, token = "play-token")
    }

    @Test
    fun `evidence signed by another key is refused`() {
        val authorization = backendWith(developmentPolicy).authorize(evidence(), signedBy = TestKey())

        assertThat(authorization.decision).isEqualTo(SensitiveActionDecision.BLOCK)
        assertThat(authorization.reasons.single().text).contains("not signed")
    }

    @Test
    fun `evidence older than the time window is refused`() {
        val stale = evidence(collectedAt = clock.now.minus(ReferenceSigningScheme.TIME_WINDOW).minusSeconds(1).toString())

        assertThat(backendWith(developmentPolicy).authorize(stale).reasons.single().text).contains("out of date")
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
        assertThat(authorization.reasons.joinToString { it.text }).contains("Demo phones not accepted")
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

        assertThat(authorization.reasons.joinToString { it.text }).contains("different request")
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
        assertThat(authorization.reasons.joinToString { it.text }).contains("test mode")
    }

    @Test
    fun `a phone without strong integrity has to confirm`() {
        val authorization = authorizeWithVerdict { it.copy(deviceRecognition = setOf(PlayIntegrityLabels.MEETS_DEVICE_INTEGRITY)) }

        assertThat(authorization.decision).isEqualTo(SensitiveActionDecision.REQUIRE_CONFIRMATION)
        assertThat(authorization.reasons.map { it.text }).contains("Play Integrity: not strong")
    }

    @Test
    fun `an app that can see or control the screen blocks the payment until it's closed`() {
        val unknown = authorizeWithVerdict { it.copy(appsDetected = setOf(PlayIntegrityLabels.UNKNOWN_CAPTURING)) }
        val remoteHelp = authorizeWithVerdict {
            it.copy(appsDetected = setOf(PlayIntegrityLabels.KNOWN_CONTROLLING, PlayIntegrityLabels.UNKNOWN_OVERLAYS))
        }

        assertThat(unknown.decision).isEqualTo(SensitiveActionDecision.BLOCK)
        assertThat(unknown.remedy).isEqualTo(Remedy.CLOSE_UNKNOWN_ACCESS_RISK)
        assertThat(remoteHelp.decision).isEqualTo(SensitiveActionDecision.BLOCK)
        assertThat(remoteHelp.reasons.map { it.text }).contains("Remote-control app running")
        assertThat(remoteHelp.remedy).isEqualTo(Remedy.CLOSE_ALL_ACCESS_RISK)
        assertThat(remoteHelp.scamWarning).isTrue()
    }

    @Test
    fun `a screen-capturing app or an unknown overlay asks for confirmation`() {
        val authorization = authorizeWithVerdict { it.copy(appsDetected = setOf(PlayIntegrityLabels.KNOWN_CAPTURING, PlayIntegrityLabels.KNOWN_OVERLAYS)) }

        assertThat(authorization.decision).isEqualTo(SensitiveActionDecision.REQUIRE_CONFIRMATION)
        assertThat(authorization.remedy).isEqualTo(Remedy.CLOSE_ALL_ACCESS_RISK)
    }

    @Test
    fun `Play Protect finding dangerous apps blocks, and Play Protect turned off asks for confirmation`() {
        val dangerous = authorizeWithVerdict { it.copy(playProtect = PlayIntegrityLabels.PLAY_PROTECT_HIGH_RISK) }
        val off = authorizeWithVerdict { it.copy(playProtect = PlayIntegrityLabels.PLAY_PROTECT_OFF) }

        assertThat(dangerous.decision).isEqualTo(SensitiveActionDecision.BLOCK)
        assertThat(off.decision).isEqualTo(SensitiveActionDecision.REQUIRE_CONFIRMATION)
        assertThat(off.remedy).isEqualTo(Remedy.FIX_PLAY_PROTECT)
    }

    @Test
    fun `a copy not from Google Play or a phone making many integrity requests asks for confirmation`() {
        val unlicensed = authorizeWithVerdict { it.copy(appLicensing = PlayIntegrityLabels.UNLICENSED) }
        val busy = authorizeWithVerdict { it.copy(deviceActivity = PlayIntegrityLabels.ACTIVITY_LEVEL_4) }

        assertThat(unlicensed.decision).isEqualTo(SensitiveActionDecision.REQUIRE_CONFIRMATION)
        assertThat(unlicensed.remedy).isEqualTo(Remedy.GET_LICENSED)
        assertThat(busy.decision).isEqualTo(SensitiveActionDecision.REQUIRE_CONFIRMATION)
    }

    @Test
    fun `an app version older than the minimum is told to update`() {
        val evidence = evidence()
        // Registered while its version was current; Play now reports the version asking to pay.
        val authorization = backendWith(strict(genuineVerdict(evidence).copy(appVersionCode = 1), minimumAppVersionCode = 2), appVersionCode = 2)
            .authorize(evidence, token = "play-token")

        assertThat(authorization.decision).isEqualTo(SensitiveActionDecision.BLOCK)
        assertThat(authorization.remedy).isEqualTo(Remedy.UPDATE_APP)
    }

    @Test
    fun `no fix is offered when a problem it can't fix blocks the payment anyway`() {
        val evidence = evidence(listOf(ReportedSignal(SignalCatalog.ROOT_SU_PATH.id, detected = true)))
        val verdict = genuineVerdict(evidence).copy(playProtect = PlayIntegrityLabels.PLAY_PROTECT_OFF)

        val authorization = backendWith(strict(verdict)).authorize(evidence, token = "play-token")

        assertThat(authorization.decision).isEqualTo(SensitiveActionDecision.BLOCK)
        assertThat(authorization.remedy).isNull()
    }

    @Test
    fun `the development server acts on what a mock token claims`() {
        val evidence = evidence()
        val claims = MockIntegrityClaims(ReferenceSigningScheme.sha256Hex(evidence), appsDetected = setOf(PlayIntegrityLabels.UNKNOWN_CONTROLLING))

        val authorization = backendWith(developmentPolicy).authorize(evidence, token = claims.encode())

        assertThat(authorization.decision).isEqualTo(SensitiveActionDecision.BLOCK)
        assertThat(authorization.reasons.map { it.text }).contains("Play Integrity in test mode")
    }

    @Test
    fun `paying during a call asks for confirmation and warns of a scam`() {
        val authorization = backendWith(developmentPolicy).authorize(
            evidence(listOf(ReportedSignal(SignalCatalog.CALL_ACTIVE.id, detected = true))),
        )

        assertThat(authorization.decision).isEqualTo(SensitiveActionDecision.REQUIRE_CONFIRMATION)
        assertThat(authorization.scamWarning).isTrue()
    }
}

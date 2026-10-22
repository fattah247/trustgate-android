package id.fatarc.trustgate.backend

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.backend.integrity.DeviceRecallWriter
import id.fatarc.trustgate.backend.integrity.IntegrityVerdict
import id.fatarc.trustgate.domain.actiongate.SensitiveActionDecision
import id.fatarc.trustgate.domain.api.DeviceEvidence
import id.fatarc.trustgate.domain.api.MockIntegrityClaims
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.PlayIntegrityLabels
import id.fatarc.trustgate.domain.api.RecallBit
import id.fatarc.trustgate.domain.api.RegistrationResult
import id.fatarc.trustgate.domain.api.TrustGateJson
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.testing.MutableClock
import id.fatarc.trustgate.testing.TEST_PACKAGE
import id.fatarc.trustgate.testing.TEST_PAYMENT
import id.fatarc.trustgate.testing.TEST_SIGNER_DIGEST
import id.fatarc.trustgate.testing.TestAttestation
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.developmentPolicy
import id.fatarc.trustgate.testing.selfSignedChain
import id.fatarc.trustgate.testing.strictBackendPolicy
import java.time.Duration
import org.junit.Test

class DeviceRecallTest {
    private val clock = MutableClock()
    private val phone = TestKey()
    private val attestation = TestAttestation()
    private val written = mutableListOf<Pair<String, Map<RecallBit, Boolean>>>()
    private val writer = DeviceRecallWriter { token, bits -> written += token to bits }

    private fun evidence() =
        TrustGateJson.encodeToString(DeviceEvidence.serializer(), DeviceEvidence(phone.keyId, clock.now.toString(), emptyList(), payment = TEST_PAYMENT))

    private fun developmentBackend() = ReferenceBackend(developmentPolicy, clock, recallWriter = writer).apply {
        val challenge = issueRegistrationChallenge()
        check(registerKey(KeyRole.DEVICE, phone.encodedPublicKey, selfSignedChain(phone), challenge) is RegistrationResult.Registered)
    }

    /** A strict server whose Play Integrity verifier answers every token with Google's genuine verdict. */
    private fun strictBackend(recall: Set<RecallBit>?): ReferenceBackend {
        val backend = ReferenceBackend(
            strictBackendPolicy(attestation, integrity = { token ->
                IntegrityVerdict(
                    requestPackageName = TEST_PACKAGE,
                    requestHash = token.removePrefix("play:"),
                    timestampMillis = clock.now.toEpochMilli(),
                    appRecognition = PlayIntegrityLabels.PLAY_RECOGNIZED,
                    certificateDigests = setOf(TEST_SIGNER_DIGEST),
                    deviceRecognition = setOf(PlayIntegrityLabels.MEETS_DEVICE_INTEGRITY, PlayIntegrityLabels.MEETS_STRONG_INTEGRITY),
                    deviceRecall = recall,
                )
            }),
            clock,
            recallWriter = writer,
        )
        val challenge = backend.issueRegistrationChallenge()
        check(backend.registerKey(KeyRole.DEVICE, phone.encodedPublicKey, attestation.chainFor(phone.pair.public, challenge), challenge) is RegistrationResult.Registered)
        return backend
    }

    private fun ReferenceBackend.authorizeWith(token: (evidence: String) -> String): PaymentAuthorization {
        val evidence = evidence()
        return authorizePayment(phone.keyId, evidence, phone.sign(evidence.toByteArray()), token(evidence), clock.now)
    }

    private fun mockToken(vararg recall: RecallBit): (String) -> String =
        { evidence -> MockIntegrityClaims(ReferenceSigningScheme.sha256Hex(evidence), recall = recall.toSet()).encode() }

    private val playToken: (String) -> String = { evidence -> "play:" + ReferenceSigningScheme.sha256Hex(evidence) }

    @Test
    fun `a phone an operator blocked before is still blocked after it starts over`() {
        val authorization = developmentBackend().authorizeWith(mockToken(RecallBit.FIRST, RecallBit.SECOND))

        assertThat(authorization.decision).isEqualTo(SensitiveActionDecision.BLOCK)
        assertThat(authorization.reasons.map { it.text }).contains("This phone was blocked before")
    }

    @Test
    fun `a phone set up here before that arrives as new asks for confirmation`() {
        val authorization = developmentBackend().authorizeWith(mockToken(RecallBit.FIRST))

        assertThat(authorization.decision).isEqualTo(SensitiveActionDecision.REQUIRE_CONFIRMATION)
        assertThat(authorization.reasons.map { it.text }).contains("Set up again on this phone")
    }

    @Test
    fun `the first time Google vouches for a phone, it's marked as set up here`() {
        val backend = strictBackend(recall = emptySet())

        backend.authorizeWith(playToken)

        assertThat(written.single().second).containsExactly(RecallBit.FIRST, true)
    }

    @Test
    fun `revoking a phone marks it blocked on Google's side with its latest token`() {
        val backend = strictBackend(recall = setOf(RecallBit.FIRST))
        backend.authorizeWith(playToken)

        backend.revokeByOperator(phone.keyId, "fraud reported")

        assertThat(written.single().first).startsWith("play:")
        assertThat(written.single().second).containsExactly(RecallBit.SECOND, true)
    }

    @Test
    fun `a token too old for Google to accept isn't used`() {
        val backend = strictBackend(recall = setOf(RecallBit.FIRST))
        backend.authorizeWith(playToken)
        clock.advanceSeconds(Duration.ofDays(15).seconds)

        backend.revokeByOperator(phone.keyId, "fraud reported")

        assertThat(written).isEmpty()
    }

    @Test
    fun `made-up verdicts never cause writes`() {
        developmentBackend().authorizeWith(mockToken())

        assertThat(written).isEmpty()
    }
}

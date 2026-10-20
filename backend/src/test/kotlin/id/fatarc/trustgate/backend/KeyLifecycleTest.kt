package id.fatarc.trustgate.backend

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.backend.audit.AuditEntry
import id.fatarc.trustgate.backend.store.InMemoryBackendStore
import id.fatarc.trustgate.domain.actiongate.SensitiveActionDecision
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.PaymentResponse
import id.fatarc.trustgate.domain.api.RegistrationResult
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.PaymentRequestPayload
import id.fatarc.trustgate.domain.signing.ReferenceRequestSigner
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.domain.signing.RejectionReason
import id.fatarc.trustgate.domain.signing.asReceived
import id.fatarc.trustgate.testing.MutableClock
import id.fatarc.trustgate.testing.TestAttestation
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.authorize
import id.fatarc.trustgate.testing.developmentPolicy
import id.fatarc.trustgate.testing.selfSignedChain
import id.fatarc.trustgate.testing.strictBackendPolicy
import java.time.Duration
import org.junit.Test

class KeyLifecycleTest {
    private val clock = MutableClock()
    private val store = InMemoryBackendStore()
    private val device = TestKey()
    private val stepUp = TestKey()
    private val signer = ReferenceRequestSigner()
    private var paymentsSent = 0

    private fun backend(policy: BackendPolicy = developmentPolicy) = ReferenceBackend(policy, clock, store = store)

    private fun ReferenceBackend.registerPhone(): ReferenceBackend = apply {
        val challenge = issueRegistrationChallenge()
        check(registerKey(KeyRole.DEVICE, device.encodedPublicKey, selfSignedChain(device), challenge) is RegistrationResult.Registered)
        val stepUpChallenge = issueRegistrationChallenge(device.keyId)
        val proof = device.sign(ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_ADD_STEP_UP, stepUpChallenge, stepUp.keyId))
        check(registerKey(KeyRole.STEP_UP, stepUp.encodedPublicKey, selfSignedChain(stepUp), stepUpChallenge, device.keyId, proof) is RegistrationResult.Registered)
    }

    private fun ReferenceBackend.rotate(to: TestKey, vouchedBy: TestKey = device, chain: List<ByteArray> = selfSignedChain(to)): RegistrationResult {
        val challenge = issueRegistrationChallenge(device.keyId)
        val proof = vouchedBy.sign(ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_ROTATE_DEVICE, challenge, to.keyId))
        return rotateDeviceKey(device.keyId, to.encodedPublicKey, chain, challenge, proof)
    }

    private fun ReferenceBackend.pay(key: TestKey): PaymentResponse {
        val nonce = (authorize(key, DeviceRiskLevel.LOW, clock.now) as PaymentAuthorization.Proceed).nonce
        val request = key.sign(
            signer.prepare(
                PaymentRequestPayload(125_000, "IDR", "REF-${++paymentsSent}"),
                nonce,
                key.keyId,
                clock.now.toString(),
                idempotencyKey = "idem-$paymentsSent",
            ),
        )
        return submitPayment(request.asReceived(), clock.now)
    }

    @Test
    fun `a rotated key takes over the phone, and the old keys are never accepted again`() {
        val backend = backend().registerPhone()
        val next = TestKey()

        val rotated = backend.rotate(next)
        val oldAuthorization = backend.authorize(device, DeviceRiskLevel.LOW, clock.now)

        assertThat(rotated).isInstanceOf(RegistrationResult.Registered::class.java)
        assertThat(oldAuthorization).isInstanceOf(PaymentAuthorization.Blocked::class.java)
        assertThat((oldAuthorization as PaymentAuthorization.Blocked).keyRejected).isTrue()
        assertThat(store.key(stepUp.keyId)?.isRevoked).isTrue()
        assertThat(backend.pay(next)).isInstanceOf(PaymentResponse.Processed::class.java)
    }

    @Test
    fun `a request signed by a replaced key is refused as revoked`() {
        val backend = backend().registerPhone()
        val nonce = (backend.authorize(device, DeviceRiskLevel.LOW, clock.now) as PaymentAuthorization.Proceed).nonce
        backend.rotate(TestKey())

        val late = device.sign(signer.prepare(PaymentRequestPayload(125_000, "IDR", "REF-1"), nonce, device.keyId, clock.now.toString(), idempotencyKey = "idem-1"))

        assertThat(backend.submitPayment(late.asReceived(), clock.now)).isEqualTo(PaymentResponse.Rejected(RejectionReason.KEY_REVOKED))
    }

    @Test
    fun `only the current key can hand over to a new one`() {
        val backend = backend().registerPhone()

        val result = backend.rotate(TestKey(), vouchedBy = TestKey())

        assertThat(result).isInstanceOf(RegistrationResult.Refused::class.java)
        assertThat(store.key(device.keyId)?.isRevoked).isFalse()
    }

    @Test
    fun `an attested phone can't rotate to a key that proves less`() {
        val attestation = TestAttestation()
        val backend = backend(strictBackendPolicy(attestation, integrity = { null }))
        val challenge = backend.issueRegistrationChallenge()
        backend.registerKey(KeyRole.DEVICE, device.encodedPublicKey, attestation.chainFor(device.pair.public, challenge), challenge)
        val next = TestKey()

        val toSelfSigned = backend.rotate(next, chain = selfSignedChain(next))

        assertThat(toSelfSigned).isInstanceOf(RegistrationResult.Refused::class.java)
    }

    @Test
    fun `rotating keeps the phone's payment history, so limits can't be reset by a new key`() {
        val limits = PaymentLimits(maxPayments = 1, window = Duration.ofMinutes(1), dailyAmountMinor = null, newPhonePeriod = null, newPhoneAmountMinor = null)
        val backend = backend(BackendPolicy(developmentPolicy.name, developmentPolicy.attestation, developmentPolicy.risk, limits)).registerPhone()
        backend.pay(device)
        val next = TestKey()

        backend.rotate(next)

        assertThat(backend.authorize(next, DeviceRiskLevel.LOW, clock.now).decision).isEqualTo(SensitiveActionDecision.BLOCK)
    }

    @Test
    fun `a phone can remove itself, and an operator can revoke a phone by either key`() {
        val backend = backend().registerPhone()
        val challenge = backend.issueRegistrationChallenge(device.keyId)
        val proof = device.sign(ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_REMOVE_DEVICE, challenge, device.keyId))

        assertThat(backend.removeDevice(device.keyId, challenge, proof)).isTrue()
        assertThat(backend.revokeByOperator(stepUp.keyId, "reported stolen")).isFalse()

        val other = TestKey()
        val otherChallenge = backend.issueRegistrationChallenge()
        backend.registerKey(KeyRole.DEVICE, other.encodedPublicKey, selfSignedChain(other), otherChallenge)
        assertThat(backend.revokeByOperator(other.keyId, "fraud reported")).isTrue()
        assertThat((backend.authorize(other, DeviceRiskLevel.LOW, clock.now) as PaymentAuthorization.Blocked).reasons.single().text)
            .isEqualTo("Phone removed")
    }

    @Test
    fun `the audit log records what happened and stays intact`() {
        val backend = backend().registerPhone()
        backend.pay(device)
        backend.rotate(TestKey())

        val status = backend.auditStatus()

        assertThat(status.intact).isTrue()
        assertThat(status.entries).isAtLeast(5)
        assertThat(store.auditEntries().map { it.event }.toList())
            .containsAtLeast("key-registered", "payment-authorized", "payment-charged", "key-rotated").inOrder()
    }

    @Test
    fun `changing an audit entry breaks the chain from that entry on`() {
        val backend = backend().registerPhone()
        backend.pay(device)
        val charged = store.auditEntries().first { it.event == "payment-charged" }

        store.replaceAuditEntry(
            AuditEntry(charged.sequence, charged.at, charged.event, charged.subject, "PAY-FORGED 1 IDR", charged.previousHash, charged.hash),
        )
        val status = backend.auditStatus()

        assertThat(status.intact).isFalse()
        assertThat(status.brokenAt).isEqualTo(charged.sequence)
    }
}

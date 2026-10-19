package id.fatarc.trustgate.server

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.backend.ReferenceBackend
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.PaymentResponse
import id.fatarc.trustgate.domain.api.RegistrationResult
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReferencePayment
import id.fatarc.trustgate.domain.signing.ReferenceRequestSigner
import id.fatarc.trustgate.domain.signing.RejectionReason
import id.fatarc.trustgate.domain.signing.asReceived
import id.fatarc.trustgate.testing.MutableClock
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.authorize
import id.fatarc.trustgate.testing.developmentPolicy
import id.fatarc.trustgate.testing.selfSignedChain
import java.io.File
import org.junit.After
import org.junit.Test

class SqliteBackendStoreTest {
    private val file = File.createTempFile("trustgate", ".db")
    private val clock = MutableClock()
    private val device = TestKey()
    private val stores = mutableListOf<SqliteBackendStore>()

    private fun backend() = ReferenceBackend(developmentPolicy, clock, store = SqliteBackendStore(file).also(stores::add))

    @After
    fun tearDown() {
        stores.forEach(SqliteBackendStore::close)
        file.delete()
    }

    @Test
    fun `keys, spent challenges, and charged payments survive a restart`() {
        val before = backend()
        val challenge = before.issueRegistrationChallenge()
        assertThat(before.registerKey(KeyRole.DEVICE, device.encodedPublicKey, selfSignedChain(device), challenge))
            .isInstanceOf(RegistrationResult.Registered::class.java)
        val nonce = (before.authorize(device, DeviceRiskLevel.LOW, clock.now) as PaymentAuthorization.Proceed).nonce
        val payment = device.sign(
            ReferenceRequestSigner().prepare(ReferencePayment.payload(), nonce, device.keyId, clock.now.toString(), idempotencyKey = "idem-1"),
        ).asReceived()
        val charged = before.submitPayment(payment) as PaymentResponse.Processed

        val after = backend()
        val repeat = after.submitPayment(payment) as PaymentResponse.Processed
        val reusedRegistration = after.registerKey(KeyRole.DEVICE, TestKey().encodedPublicKey, selfSignedChain(TestKey()), challenge)

        assertThat(repeat.replayed).isTrue()
        assertThat(repeat.payment).isEqualTo(charged.payment)
        assertThat(after.chargedPayments).isEqualTo(1)
        assertThat(reusedRegistration).isInstanceOf(RegistrationResult.Refused::class.java)
    }

    @Test
    fun `a spent challenge is still recognised as a replay after a restart`() {
        val before = backend()
        before.registerKey(KeyRole.DEVICE, device.encodedPublicKey, selfSignedChain(device), before.issueRegistrationChallenge())
        val nonce = before.issueVerificationChallenge(device.keyId)
        val request = device.sign(ReferenceRequestSigner().prepare(ReferencePayment.payload(), nonce, device.keyId, clock.now.toString())).asReceived()
        before.authenticate(request)

        assertThat(backend().authenticate(request).toString()).contains(RejectionReason.CHALLENGE_REUSED.name)
    }
}

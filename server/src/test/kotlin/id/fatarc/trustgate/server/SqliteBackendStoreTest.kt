package id.fatarc.trustgate.server

import id.fatarc.trustgate.testing.TEST_PAYMENT
import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.backend.ReferenceBackend
import id.fatarc.trustgate.domain.api.Payment
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.PaymentResponse
import id.fatarc.trustgate.domain.api.RegistrationResult
import id.fatarc.trustgate.domain.api.RequiredConfirmation
import id.fatarc.trustgate.domain.api.TrustGateJson
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReferencePayment
import id.fatarc.trustgate.domain.signing.ReferenceRequestSigner
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.domain.signing.RejectionReason
import id.fatarc.trustgate.domain.signing.asReceived
import id.fatarc.trustgate.testing.MutableClock
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.authorize
import id.fatarc.trustgate.testing.decideAbout
import id.fatarc.trustgate.testing.developmentPolicy
import id.fatarc.trustgate.testing.selfSignedChain
import id.fatarc.trustgate.testing.signedAction
import java.io.File
import java.sql.DriverManager
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
            ReferenceRequestSigner().prepare(TEST_PAYMENT, nonce, device.keyId, clock.now.toString(), idempotencyKey = "idem-1"),
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
        val request = device.sign(ReferenceRequestSigner().prepare(TEST_PAYMENT, nonce, device.keyId, clock.now.toString())).asReceived()
        before.authenticate(request)

        assertThat(backend().authenticate(request).toString()).contains(RejectionReason.CHALLENGE_REUSED.name)
    }

    @Test
    fun `a database from before ledger times and phones were stored is brought up to date with its keys and payments kept`() {
        val payment = Payment("PAY-1", 125_000, "IDR", KeyRole.DEVICE, RequiredConfirmation.NONE, clock.now.toString())
        DriverManager.getConnection("jdbc:sqlite:${file.path}").use { old ->
            old.createStatement().use {
                it.execute(
                    """CREATE TABLE ledger (
                        device_key_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, fingerprint TEXT NOT NULL, payment TEXT NOT NULL,
                        PRIMARY KEY (device_key_id, idempotency_key))""",
                )
            }
            old.createStatement().use {
                it.execute(
                    """CREATE TABLE keys (
                        key_id TEXT PRIMARY KEY, role TEXT NOT NULL, public_key BLOB NOT NULL, device_key_id TEXT NOT NULL,
                        attested INTEGER NOT NULL, root_fingerprint TEXT, registered_at INTEGER NOT NULL)""",
                )
            }
            old.prepareStatement("INSERT INTO keys VALUES (?, 'DEVICE', ?, ?, 0, NULL, ?)").use {
                it.setString(1, device.keyId)
                it.setBytes(2, device.encodedPublicKey)
                it.setString(3, device.keyId)
                it.setLong(4, clock.now.toEpochMilli())
                it.executeUpdate()
            }
            old.prepareStatement("INSERT INTO ledger VALUES (?, ?, ?, ?)").use {
                it.setString(1, device.keyId)
                it.setString(2, "idem-old")
                it.setString(3, "fingerprint")
                it.setString(4, TrustGateJson.encodeToString(Payment.serializer(), payment))
                it.executeUpdate()
            }
        }

        val store = SqliteBackendStore(file).also(stores::add)

        // Each phone from before is the only phone on an account of its own.
        val account = checkNotNull(store.phone(device.keyId)).accountId
        assertThat(store.paymentsOfAccount(account, clock.now.minusSeconds(60))).containsExactly(payment)
        assertThat(store.paymentsOfAccount(account, clock.now.plusSeconds(1))).isEmpty()
        assertThat(store.key(device.keyId)?.phoneId).isEqualTo(device.keyId)
        assertThat(store.key(device.keyId)?.phoneEnrolledAt).isEqualTo(clock.now)
    }

    @Test
    fun `the audit chain survives a restart, and an edit made straight to the database is caught`() {
        val before = backend()
        val challenge = before.issueRegistrationChallenge()
        before.registerKey(KeyRole.DEVICE, device.encodedPublicKey, selfSignedChain(device), challenge)
        before.revokeByOperator(device.keyId, "fraud reported")

        val store = SqliteBackendStore(file).also(stores::add)
        val after = ReferenceBackend(developmentPolicy, clock, store = store)
        val intact = after.auditStatus()
        store.overwriteAuditDetail(sequence = 1, detail = "nothing happened")
        val edited = after.auditStatus()

        assertThat(intact.intact).isTrue()
        assertThat(intact.entries).isEqualTo(2)
        assertThat(edited.intact).isFalse()
        assertThat(edited.brokenAt).isEqualTo(1)
    }

    @Test
    fun `a link code, a phone waiting to join, and the approval each survive a restart`() {
        val second = TestKey()
        val first = backend()
        listOf(device, second).forEach { key ->
            first.registerKey(KeyRole.DEVICE, key.encodedPublicKey, selfSignedChain(key), first.issueRegistrationChallenge())
        }
        val code = checkNotNull(first.createLinkCode(first.signedAction(device, ReferenceSigningScheme.ACTION_LINK_CODE))).code

        val afterCode = backend()
        val joined = afterCode.joinAccount(afterCode.signedAction(second, ReferenceSigningScheme.ACTION_JOIN_ACCOUNT, code))
        val afterJoin = backend()
        val approved = afterJoin.decideAbout(device, second, ReferenceSigningScheme.DECISION_APPROVE)
        val afterApproval = backend()
        val view = checkNotNull(afterApproval.accountView(afterApproval.signedAction(second, ReferenceSigningScheme.ACTION_VIEW_ACCOUNT)))

        assertThat(joined.waitingForApproval).isTrue()
        assertThat(approved).isTrue()
        assertThat(view.phones.map { it.phoneId }).containsExactly(device.keyId, second.keyId)
        assertThat(afterApproval.auditStatus().intact).isTrue()
    }

    @Test
    fun `a revoked key stays revoked after a restart`() {
        val before = backend()
        val challenge = before.issueRegistrationChallenge()
        before.registerKey(KeyRole.DEVICE, device.encodedPublicKey, selfSignedChain(device), challenge)
        before.revokeByOperator(device.keyId, "fraud reported")

        val after = backend()

        assertThat((after.authorize(device, DeviceRiskLevel.LOW, clock.now) as PaymentAuthorization.Blocked).keyRejected).isTrue()
    }
}

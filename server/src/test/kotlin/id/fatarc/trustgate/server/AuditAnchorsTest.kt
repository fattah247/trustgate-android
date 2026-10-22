package id.fatarc.trustgate.server

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.backend.ReferenceBackend
import id.fatarc.trustgate.backend.audit.AuditAnchoring
import id.fatarc.trustgate.backend.audit.AuditCheckpoint
import id.fatarc.trustgate.domain.api.AuditStatus
import id.fatarc.trustgate.domain.api.ServerHealth
import id.fatarc.trustgate.domain.api.TrustGateJson
import id.fatarc.trustgate.domain.api.TrustGateRoutes
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.testing.MutableClock
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.developmentPolicy
import id.fatarc.trustgate.testing.selfSignedChain
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.time.Duration
import java.util.Date
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.tsp.TSPAlgorithms
import org.bouncycastle.tsp.TimeStampRequest
import org.bouncycastle.tsp.TimeStampResponseGenerator
import org.bouncycastle.tsp.TimeStampTokenGenerator
import org.bouncycastle.util.CollectionStore
import org.junit.After
import org.junit.Test

class AuditAnchorsTest {
    private val clock = MutableClock()
    private val database = File.createTempFile("trustgate", ".db")
    private val checkpoints = File.createTempFile("checkpoints", ".jsonl").also(File::delete)
    private val store = SqliteBackendStore(database)
    private val backend = ReferenceBackend(developmentPolicy, clock, store = store)
    private val anchorKey = newKeyPair()
    private val authority = LocalAuthority()
    private val adminToken = "a".repeat(40)

    @After
    fun tearDown() {
        store.close()
        database.delete()
        checkpoints.delete()
    }

    private fun anchoring(timestamper: Rfc3161Timestamper? = null) =
        AuditAnchoring(store, anchorKey.private, anchorKey.public, FileCheckpointSink(checkpoints), timestamper, clock)

    private fun logSomething() {
        val key = TestKey()
        backend.registerKey(KeyRole.DEVICE, key.encodedPublicKey, selfSignedChain(key), backend.issueRegistrationChallenge())
    }

    @Test
    fun `a timestamp from the trusted authority verifies and carries the authority's time`() {
        val timestamper = Rfc3161Timestamper(setOf(authority.fingerprint), authority::answer)
        val digest = AuditCheckpoint.digestOf(1, "0".repeat(64), clock.now.toString())

        val token = checkNotNull(timestamper.timestamp(digest))

        assertThat(timestamper.timeOf(token, digest)).isEqualTo(clock.now)
        assertThat(timestamper.timeOf(token, AuditCheckpoint.digestOf(2, "0".repeat(64), clock.now.toString()))).isNull()
    }

    @Test
    fun `a timestamp signed by any other authority doesn't count`() {
        val impostor = LocalAuthority()
        val trusting = Rfc3161Timestamper(setOf(authority.fingerprint), impostor::answer)
        val digest = AuditCheckpoint.digestOf(1, "0".repeat(64), clock.now.toString())
        val forged = checkNotNull(Rfc3161Timestamper(setOf(impostor.fingerprint), impostor::answer).timestamp(digest))

        assertThat(trusting.timestamp(digest)).isNull()
        assertThat(trusting.timeOf(forged, digest)).isNull()
    }

    @Test
    fun `checkpoints kept in a file, timestamped from outside, hold across a restart`() {
        logSomething()
        anchoring(Rfc3161Timestamper(setOf(authority.fingerprint), authority::answer)).checkpoint()
        logSomething()
        clock.advanceSeconds(60)
        anchoring(Rfc3161Timestamper(setOf(authority.fingerprint), authority::answer)).checkpoint()

        val reread = FileCheckpointSink(checkpoints).all()
        val status = anchoring(Rfc3161Timestamper(setOf(authority.fingerprint), authority::answer)).status()

        assertThat(reread.map { it.sequence }).containsExactly(1L, 2L).inOrder()
        assertThat(reread.all { it.timestampToken != null }).isTrue()
        assertThat(status.intact).isTrue()
        assertThat(status.checkpoints).isEqualTo(2)
    }

    @Test
    fun `an edit the chain alone can't show is caught against the checkpoint file`() {
        logSomething()
        anchoring().checkpoint()

        // The edit and a rebuilt chain, all inside the database: the hash at entry 1 changes.
        store.overwriteAuditDetail(sequence = 1, detail = "nothing happened")
        store.rehashAuditChain()

        assertThat(backend.auditStatus().intact).isTrue()
        assertThat(anchoring().status().intact).isFalse()
        assertThat(anchoring().status().brokenAt).isEqualTo(1)
    }

    @Test
    fun `the anchor key loads from its PKCS#12 file`() {
        val file = File.createTempFile("anchor", ".p12").also(File::deleteOnExit)
        val certificate = JcaX509CertificateConverter().getCertificate(selfSigned(anchorKey, timestamping = false))
        KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setKeyEntry("audit-anchor", anchorKey.private, "secret".toCharArray(), arrayOf(certificate))
            file.outputStream().use { store(it, "secret".toCharArray()) }
        }

        val loaded = loadAnchorKey(file, "secret")

        assertThat(loaded.public.encoded).isEqualTo(anchorKey.public.encoded)
        assertThat(loaded.private.encoded).isEqualTo(anchorKey.private.encoded)
    }

    @Test
    fun `the operator can checkpoint now and see the checkpoints in the audit status`() = testApplication {
        logSomething()
        application { trustGateModule(backend, ServerHealth(status = "ok", policy = "development"), adminToken = adminToken, anchoring = anchoring()) }

        val withoutToken = client.post(TrustGateRoutes.ADMIN_AUDIT_CHECKPOINT).status
        val made = client.post(TrustGateRoutes.ADMIN_AUDIT_CHECKPOINT) { header(HttpHeaders.Authorization, "Bearer $adminToken") }
        val audit = client.get(TrustGateRoutes.ADMIN_AUDIT) { header(HttpHeaders.Authorization, "Bearer $adminToken") }

        assertThat(withoutToken).isEqualTo(HttpStatusCode.Unauthorized)
        assertThat(TrustGateJson.decodeFromString(AuditStatus.serializer(), made.bodyAsText()).checkpoints).isEqualTo(1)
        assertThat(TrustGateJson.decodeFromString(AuditStatus.serializer(), audit.bodyAsText()).intact).isTrue()
    }

    @Test
    fun `a server that keeps no checkpoints says so`() = testApplication {
        application { trustGateModule(backend, ServerHealth(status = "ok", policy = "development"), adminToken = adminToken) }

        val response = client.post(TrustGateRoutes.ADMIN_AUDIT_CHECKPOINT) { header(HttpHeaders.Authorization, "Bearer $adminToken") }

        assertThat(response.status).isEqualTo(HttpStatusCode.NotFound)
    }

    /** A timestamping authority run in the test, on the test's clock. */
    private inner class LocalAuthority {
        private val keys = newKeyPair()
        private val certificate = selfSigned(keys, timestamping = true)
        private var serial = 1L
        val fingerprint: String = ReferenceSigningScheme.sha256Hex(certificate.encoded)

        fun answer(request: ByteArray): ByteArray {
            val generator = TimeStampTokenGenerator(
                JcaSimpleSignerInfoGeneratorBuilder().build("SHA256withECDSA", keys.private, certificate),
                JcaDigestCalculatorProviderBuilder().build().get(AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1"),
            ).apply { addCertificates(CollectionStore(listOf(certificate))) }
            return TimeStampResponseGenerator(generator, TSPAlgorithms.ALLOWED)
                .generate(TimeStampRequest(request), BigInteger.valueOf(serial++), Date.from(clock.now))
                .encoded
        }
    }

    private fun selfSigned(keys: KeyPair, timestamping: Boolean): X509CertificateHolder {
        val name = X500Name("CN=TrustGate test")
        return JcaX509v3CertificateBuilder(
            name, BigInteger.valueOf(System.nanoTime()), Date.from(clock.now.minus(Duration.ofDays(1))),
            Date.from(clock.now.plus(Duration.ofDays(365))), name, keys.public,
        ).apply {
            if (timestamping) addExtension(Extension.extendedKeyUsage, true, ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping))
        }.build(JcaContentSignerBuilder("SHA256withECDSA").build(keys.private))
    }

    private fun newKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
}

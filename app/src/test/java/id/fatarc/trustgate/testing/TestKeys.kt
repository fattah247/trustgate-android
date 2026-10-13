package id.fatarc.trustgate.testing

import id.fatarc.trustgate.domain.signing.PreparedRequest
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.domain.signing.SignedRequest
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

/** A software P-256 key standing in for a Keystore key in JVM tests. */
class TestKey {
    val pair: KeyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    val encodedPublicKey: ByteArray get() = pair.public.encoded

    val keyId: String get() = ReferenceSigningScheme.keyIdFor(encodedPublicKey)

    fun sign(data: ByteArray): ByteArray = signature().run {
        update(data)
        sign()
    }

    /** An initialized signature, the way a Keystore key hands one to the system prompt. */
    fun signature(): Signature = Signature.getInstance(ReferenceSigningScheme.SIGNATURE_ALGORITHM).apply {
        initSign(pair.private)
    }

    fun sign(prepared: PreparedRequest): SignedRequest = prepared.signedWith(sign(prepared.signingInput))
}

/** A clock the test moves by hand. */
class MutableClock(var now: Instant = Instant.parse("2026-05-31T00:00:00Z")) : Clock() {
    override fun getZone() = ZoneOffset.UTC

    override fun withZone(zone: java.time.ZoneId?): Clock = this

    override fun instant(): Instant = now

    fun advanceSeconds(seconds: Long) {
        now = now.plusSeconds(seconds)
    }
}

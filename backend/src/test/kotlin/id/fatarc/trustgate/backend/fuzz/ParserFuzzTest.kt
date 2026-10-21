package id.fatarc.trustgate.backend.fuzz

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest
import id.fatarc.trustgate.backend.attestation.Der
import id.fatarc.trustgate.backend.attestation.KeyAttestationVerifier
import id.fatarc.trustgate.backend.attestation.KeyDescriptionParser
import id.fatarc.trustgate.backend.attestation.RevocationList
import id.fatarc.trustgate.domain.api.MockIntegrityClaims
import id.fatarc.trustgate.testing.DerWriter.explicit
import id.fatarc.trustgate.testing.DerWriter.integer
import id.fatarc.trustgate.testing.DerWriter.octetString
import id.fatarc.trustgate.testing.TestAttestation
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.attestationApplicationId
import id.fatarc.trustgate.testing.keyDescription
import id.fatarc.trustgate.testing.rootOfTrust

/**
 * Feeds the parsers that read what clients send with generated input. Malformed input may be
 * refused, but only the way the parser means to refuse it: a failed `require` or `check`. Anything
 * else (an index out of bounds, a negative array size, a hang, running out of memory) is a bug,
 * and on a server it's a request someone can send on purpose.
 *
 * A normal test run replays the inputs saved under `ParserFuzzTestInputs`; with JAZZER_FUZZ=1 each
 * test generates new ones for its maxDuration.
 */
class ParserFuzzTest {
    @FuzzTest(maxDuration = "2m")
    fun derElements(data: ByteArray) = refusedCleanly {
        val reader = Der.Reader(data)
        while (reader.hasMore()) {
            val element = reader.readElement()
            if (element.constructed) element.children().forEach { if (it.constructed) it.children() }
        }
    }

    @FuzzTest(maxDuration = "2m")
    fun keyDescription(data: ByteArray) = refusedCleanly { KeyDescriptionParser.parse(data) }

    /** Starts from a well-formed KeyDescription and changes bytes in it, to reach the deeper fields. */
    @FuzzTest(maxDuration = "2m")
    fun keyDescriptionNearValid(data: FuzzedDataProvider) {
        val bytes = VALID_KEY_DESCRIPTION.copyOf()
        repeat(data.consumeInt(1, 8)) {
            val position = data.consumeInt(0, bytes.lastIndex)
            bytes[position] = data.consumeByte()
        }
        val input = if (data.consumeBoolean()) bytes.copyOf(data.consumeInt(0, bytes.size)) else bytes
        refusedCleanly { KeyDescriptionParser.parse(input) }
    }

    /** The whole registration check never throws, whatever certificates a client sends. */
    @FuzzTest(maxDuration = "2m")
    fun attestationChain(data: FuzzedDataProvider) {
        val chain = List(data.consumeInt(0, 3)) { data.consumeBytes(2048) }
        KeyAttestationVerifier.verify(chain, data.consumeBytes(256), data.consumeRemainingAsBytes())
    }

    @FuzzTest(maxDuration = "2m")
    fun revocationList(document: String?) = refusedCleanly { RevocationList.parse(document ?: return) }

    /** A development server reads these from any client; decoding never fails, it just finds nothing. */
    @FuzzTest(maxDuration = "2m")
    fun mockIntegrityToken(token: String?) {
        val claims = MockIntegrityClaims.decode(token ?: return) ?: return
        // What decoding found encodes back to a token that decodes the same way.
        check(MockIntegrityClaims.decode(claims.encode()) == claims) { "Claims didn't survive a round trip: $token" }
    }

    private inline fun refusedCleanly(block: () -> Unit) {
        try {
            block()
        } catch (expected: IllegalArgumentException) {
            // Refused as malformed.
        } catch (expected: IllegalStateException) {
            // Refused as malformed.
        }
    }

    private companion object {
        val VALID_KEY_DESCRIPTION: ByteArray = keyDescription(
            challenge = "challenge".toByteArray(),
            softwareEnforced = listOf(explicit(709, octetString(attestationApplicationId("id.fatarc.trustgate", "ab".repeat(32))))),
            hardwareEnforced = listOf(
                explicit(702, integer(0)),
                explicit(704, rootOfTrust(locked = true, bootState = 0)),
                explicit(706, integer(202609)),
            ),
        )

        init {
            // The starting point must parse, or the near-valid test explores nothing useful.
            check(KeyDescriptionParser.parse(VALID_KEY_DESCRIPTION).rootOfTrust != null)
            check(KeyAttestationVerifier.verify(TestAttestation().chainFor(TestKey().pair.public, ByteArray(4)), ByteArray(0), ByteArray(0)).chainLength == 2)
        }
    }
}

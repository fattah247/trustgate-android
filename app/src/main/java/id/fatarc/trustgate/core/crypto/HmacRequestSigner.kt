package id.fatarc.trustgate.core.crypto

import id.fatarc.trustgate.domain.signing.PaymentRequestPayload
import id.fatarc.trustgate.domain.signing.RequestSigner
import id.fatarc.trustgate.domain.signing.SignedRequest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class HmacRequestSigner(
    private val referenceSecret: String = ReferenceSigningScheme.REFERENCE_SECRET,
) : RequestSigner {
    private val canonicalJson = Json {
        encodeDefaults = true
    }

    override fun canonicalize(payload: PaymentRequestPayload): String = canonicalJson.encodeToString(payload)

    override fun sign(
        payload: PaymentRequestPayload,
        timestamp: String,
        nonce: String,
    ): SignedRequest {
        val canonicalBody = canonicalize(payload)
        val bodyHash = ReferenceSigningScheme.sha256Hex(canonicalBody)
        val signingInput = ReferenceSigningScheme.signingInput(
            method = ReferenceSigningScheme.METHOD,
            path = ReferenceSigningScheme.PATH,
            timestamp = timestamp,
            nonce = nonce,
            bodyHash = bodyHash,
        )
        val signature = ReferenceSigningScheme.encode(ReferenceSigningScheme.hmacSha256(referenceSecret, signingInput))
        return SignedRequest(
            method = ReferenceSigningScheme.METHOD,
            path = ReferenceSigningScheme.PATH,
            payload = payload,
            canonicalBody = canonicalBody,
            bodyHash = bodyHash,
            timestamp = timestamp,
            nonce = nonce,
            signature = signature,
            headers = mapOf(
                ReferenceSigningScheme.HEADER_TIMESTAMP to timestamp,
                ReferenceSigningScheme.HEADER_NONCE to nonce,
                ReferenceSigningScheme.HEADER_SIGNATURE to signature,
            ),
        )
    }
}

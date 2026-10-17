package id.fatarc.trustgate.domain.signing

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class ReferenceRequestSigner {
    private val canonicalJson = Json {
        encodeDefaults = true
    }

    /** The exact body bytes that get hashed for [payload]. */
    fun canonicalize(payload: PaymentRequestPayload): String = canonicalJson.encodeToString(payload)

    /** Settles every signed field for a request; the key holder then signs the result. */
    fun prepare(
        payload: PaymentRequestPayload,
        nonce: String,
        keyId: String,
        timestamp: String,
        idempotencyKey: String? = null,
        confirmation: String? = null,
    ): PreparedRequest {
        val canonicalBody = canonicalize(payload)
        val bodyHash = ReferenceSigningScheme.sha256Hex(canonicalBody)
        return PreparedRequest(
            method = ReferenceSigningScheme.METHOD,
            path = ReferenceSigningScheme.PATH,
            payload = payload,
            canonicalBody = canonicalBody,
            bodyHash = bodyHash,
            timestamp = timestamp,
            nonce = nonce,
            keyId = keyId,
            idempotencyKey = idempotencyKey,
            confirmation = confirmation,
            signingInput = ReferenceSigningScheme.signingInput(
                method = ReferenceSigningScheme.METHOD,
                path = ReferenceSigningScheme.PATH,
                timestamp = timestamp,
                nonce = nonce,
                keyId = keyId,
                idempotencyKey = idempotencyKey,
                confirmation = confirmation,
                bodyHash = bodyHash,
            ),
        )
    }
}

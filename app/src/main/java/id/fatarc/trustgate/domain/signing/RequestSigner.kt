package id.fatarc.trustgate.domain.signing

interface RequestSigner {
    /** The exact body bytes this signer hashes for [payload]. */
    fun canonicalize(payload: PaymentRequestPayload): String

    fun sign(
        payload: PaymentRequestPayload,
        timestamp: String,
        nonce: String,
    ): SignedRequest
}


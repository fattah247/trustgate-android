package id.fatarc.trustgate.domain.signing

interface RequestSigner {
    fun sign(
        payload: PaymentRequestPayload,
        timestamp: String,
        nonce: String,
    ): SignedRequest
}


package id.fatarc.trustgate.domain.signing

import java.time.LocalDate

/** The one payment-like request the lab signs, shared by the protected action and the signing screen. */
object ReferencePayment {
    const val AMOUNT_MINOR = 125_000L
    const val CURRENCY = "IDR"

    fun payload(date: LocalDate = LocalDate.now()): PaymentRequestPayload = PaymentRequestPayload(
        amountMinor = AMOUNT_MINOR,
        currency = CURRENCY,
        merchantReference = "TG-$date",
    )
}

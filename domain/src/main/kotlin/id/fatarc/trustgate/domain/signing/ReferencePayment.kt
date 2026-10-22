package id.fatarc.trustgate.domain.signing

import java.time.LocalDate

/** Someone the demo can pay. [id] is what's signed; [name] is what people see. */
data class Payee(val id: String, val name: String)

/** The payments the demo can make: a few payees and amounts, each a real signed request. */
object ReferencePayment {
    const val AMOUNT_MINOR = 125_000L
    const val CURRENCY = "IDR"

    val STORE = Payee("trustgate-store", "TrustGate Store")
    val PAYEES = listOf(
        STORE,
        Payee("warung-sari", "Warung Sari"),
        Payee("new-seller-7731", "Seller you haven't paid before"),
    )

    /** IDR 1,250.00, 75,000.00, and 2,500,000.00. */
    val AMOUNTS_MINOR = listOf(AMOUNT_MINOR, 7_500_000L, 250_000_000L)

    fun payee(id: String): Payee? = PAYEES.firstOrNull { it.id == id }

    fun payload(
        payee: Payee = STORE,
        amountMinor: Long = AMOUNT_MINOR,
        date: LocalDate = LocalDate.now(),
    ): PaymentRequestPayload = PaymentRequestPayload(
        amountMinor = amountMinor,
        currency = CURRENCY,
        merchantReference = "TG-$date",
        payee = payee.id,
    )
}

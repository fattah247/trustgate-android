package id.fatarc.trustgate.backend

import java.time.Duration

/**
 * How much one phone may pay, enforced when each payment is charged. A stolen session or a
 * scripted attack runs into these however convincing its device looks.
 */
class PaymentLimits(
    /** At most this many payments per phone within [window]. */
    val maxPayments: Int,
    val window: Duration,
    /** The most a phone may pay in any 24 hours, in minor units; null for no cap. */
    val dailyAmountMinor: Long?,
    /** How long a newly registered phone counts as new; null turns the new-phone rules off. */
    val newPhonePeriod: Duration?,
    /** The most a new phone may pay at once, in minor units. */
    val newPhoneAmountMinor: Long?,
) {
    companion object {
        /** IDR amounts: 10,000,000 a day, and 1,000,000 a payment for the first day of a phone. */
        fun strict() = PaymentLimits(
            maxPayments = 5,
            window = Duration.ofMinutes(10),
            dailyAmountMinor = 1_000_000_000,
            newPhonePeriod = Duration.ofDays(1),
            newPhoneAmountMinor = 100_000_000,
        )

        /** Low enough to reach by hand on an emulator, without the new-phone rules every reinstall would hit. */
        fun development() = PaymentLimits(
            maxPayments = 3,
            window = Duration.ofMinutes(1),
            dailyAmountMinor = 1_000_000_000,
            newPhonePeriod = null,
            newPhoneAmountMinor = null,
        )

        val NONE = PaymentLimits(Int.MAX_VALUE, Duration.ofMinutes(1), null, null, null)
    }
}

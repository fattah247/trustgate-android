package id.fatarc.trustgate.backend.store

import id.fatarc.trustgate.backend.audit.AuditEntry
import id.fatarc.trustgate.domain.api.Payment
import id.fatarc.trustgate.domain.api.RequiredConfirmation
import id.fatarc.trustgate.domain.signing.KeyRole
import java.time.Instant

/** A registered key, with the facts later registrations are checked against. */
class StoredKey(
    val keyId: String,
    val role: KeyRole,
    val encodedPublicKey: ByteArray,
    /** The device key this key belongs to; a device key belongs to itself. */
    val deviceKeyId: String,
    val attested: Boolean,
    val rootKeyFingerprint: String?,
    val registeredAt: Instant,
    /** The phone the key belongs to. It stays the same when the phone replaces its device key. */
    val phoneId: String,
    /** When the phone's first device key was registered, which a replacement key keeps. */
    val phoneEnrolledAt: Instant,
    /** Set once the key is replaced or the phone removed; a revoked key is never accepted again. */
    val revokedAt: Instant? = null,
    val revokedReason: String? = null,
) {
    val isRevoked: Boolean get() = revokedAt != null

    fun revoked(at: Instant, reason: String) = StoredKey(
        keyId, role, encodedPublicKey, deviceKeyId, attested, rootKeyFingerprint, registeredAt, phoneId, phoneEnrolledAt, at, reason,
    )
}

enum class ChallengePurpose { REGISTRATION, VERIFICATION, PAYMENT }

class StoredChallenge(
    val nonce: String,
    val purpose: ChallengePurpose,
    /** The device the challenge was issued to; null only for registering a new device key. */
    val deviceKeyId: String?,
    val confirmation: RequiredConfirmation,
    val expiresAt: Instant,
    /** SHA-256 of what the challenge was issued for, such as the exact payment; the request must match it. */
    val boundHash: String? = null,
)

class LedgerEntry(
    /** What the charged request was, so a repeat can be told from a different payment under the same key. */
    val fingerprint: String,
    val payment: Payment,
)

/** Where the backend keeps its state. Every call that changes something runs inside [transaction]. */
interface BackendStore {
    /** Runs [block] so that everything it writes lands together, or none of it does. */
    fun <T> transaction(block: () -> T): T

    fun key(keyId: String): StoredKey?

    fun putKey(key: StoredKey)

    fun deleteKey(keyId: String)

    fun stepUpKeyOf(deviceKeyId: String): String?

    /** Binds [keyId] as [deviceKeyId]'s step-up key, or unbinds it when [keyId] is null. */
    fun setStepUpKey(deviceKeyId: String, keyId: String?)

    fun putChallenge(challenge: StoredChallenge)

    fun challenge(nonce: String): StoredChallenge?

    /** Removes the challenge, so it can't be used again, and remembers it was spent at [at]. */
    fun spendChallenge(nonce: String, at: Instant)

    fun isSpent(nonce: String): Boolean

    fun prune(challengesExpiredBefore: Instant, spentBefore: Instant)

    fun ledgerEntry(deviceKeyId: String, idempotencyKey: String): LedgerEntry?

    fun putLedgerEntry(deviceKeyId: String, idempotencyKey: String, entry: LedgerEntry)

    fun ledgerSize(): Int

    /** What [phoneId] was charged at or after [since], with any of its device keys, oldest first. */
    fun paymentsSince(phoneId: String, since: Instant): List<Payment>

    fun appendAuditEntry(entry: AuditEntry)

    fun lastAuditEntry(): AuditEntry?

    /** Every audit entry, in sequence order. */
    fun auditEntries(): Sequence<AuditEntry>
}

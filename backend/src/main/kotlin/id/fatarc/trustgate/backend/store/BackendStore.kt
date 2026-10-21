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

enum class ChallengePurpose { REGISTRATION, VERIFICATION, PAYMENT, DECISION }

/** A phone and the account it belongs to. Its keys come and go; the phone stays. */
class StoredPhone(
    val phoneId: String,
    val accountId: String,
    /** The phone's model, as it said when it registered. */
    val label: String,
    /** When the phone joined [accountId]; the new-phone rules count from here. */
    val joinedAt: Instant,
    /** The account the phone asked to join with a link code, until a phone on it decides. */
    val pendingAccountId: String? = null,
) {
    fun copy(accountId: String = this.accountId, joinedAt: Instant = this.joinedAt, pendingAccountId: String? = this.pendingAccountId) =
        StoredPhone(phoneId, accountId, label, joinedAt, pendingAccountId)
}

/** A one-time code a phone on [accountId] made, so another phone can ask to join. */
class StoredLinkCode(
    val code: String,
    val accountId: String,
    val issuedBy: String,
    val expiresAt: Instant,
)

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

    /** What the phones now on [accountId] were charged at or after [since], oldest first. */
    fun paymentsOfAccount(accountId: String, since: Instant): List<Payment>

    fun phone(phoneId: String): StoredPhone?

    fun putPhone(phone: StoredPhone)

    /** The phones on [accountId], and those waiting to join it. */
    fun phonesOf(accountId: String): List<StoredPhone>

    /** The phone's device key that's still accepted, if any. */
    fun activeDeviceKey(phoneId: String): StoredKey?

    /** Stores [code], replacing any other code the same account had. */
    fun putLinkCode(code: StoredLinkCode)

    fun linkCode(code: String): StoredLinkCode?

    fun deleteLinkCode(code: String)

    fun appendAuditEntry(entry: AuditEntry)

    fun lastAuditEntry(): AuditEntry?

    /** Every audit entry, in sequence order. */
    fun auditEntries(): Sequence<AuditEntry>
}

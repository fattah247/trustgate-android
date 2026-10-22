package id.fatarc.trustgate.backend.store

import id.fatarc.trustgate.backend.audit.AuditEntry
import id.fatarc.trustgate.domain.api.Payment
import id.fatarc.trustgate.domain.signing.KeyRole
import java.time.Instant

/** Keeps everything in memory, for tests and for running the backend inside one process. */
class InMemoryBackendStore : BackendStore {
    private val keys = HashMap<String, StoredKey>()
    private val stepUpKeys = HashMap<String, String>()
    private val challenges = HashMap<String, StoredChallenge>()
    private val spent = HashMap<String, Instant>()
    private val ledger = HashMap<Pair<String, String>, LedgerEntry>()
    private val audit = mutableListOf<AuditEntry>()
    private val phones = HashMap<String, StoredPhone>()
    private val linkCodes = HashMap<String, StoredLinkCode>()

    @Synchronized
    override fun <T> transaction(block: () -> T): T = block()

    override fun key(keyId: String): StoredKey? = keys[keyId]

    override fun putKey(key: StoredKey) {
        keys[key.keyId] = key
    }

    override fun deleteKey(keyId: String) {
        keys.remove(keyId)
    }

    override fun stepUpKeyOf(deviceKeyId: String): String? = stepUpKeys[deviceKeyId]

    override fun setStepUpKey(deviceKeyId: String, keyId: String?) {
        if (keyId == null) stepUpKeys.remove(deviceKeyId) else stepUpKeys[deviceKeyId] = keyId
    }

    override fun putChallenge(challenge: StoredChallenge) {
        challenges[challenge.nonce] = challenge
    }

    override fun challenge(nonce: String): StoredChallenge? = challenges[nonce]

    override fun spendChallenge(nonce: String, at: Instant) {
        challenges.remove(nonce)
        spent[nonce] = at
    }

    override fun isSpent(nonce: String): Boolean = nonce in spent

    override fun prune(challengesExpiredBefore: Instant, spentBefore: Instant) {
        challenges.values.removeAll { it.expiresAt.isBefore(challengesExpiredBefore) }
        spent.values.removeAll { it.isBefore(spentBefore) }
    }

    override fun ledgerEntry(deviceKeyId: String, idempotencyKey: String): LedgerEntry? = ledger[deviceKeyId to idempotencyKey]

    override fun putLedgerEntry(deviceKeyId: String, idempotencyKey: String, entry: LedgerEntry) {
        ledger[deviceKeyId to idempotencyKey] = entry
    }

    override fun ledgerSize(): Int = ledger.size

    override fun paymentsOfAccount(accountId: String, since: Instant): List<Payment> = ledger
        .filterKeys { (device, _) -> keys[device]?.phoneId?.let(phones::get)?.accountId == accountId }
        .values
        .map { it.payment }
        .filter { !Instant.parse(it.processedAt).isBefore(since) }
        .sortedBy { Instant.parse(it.processedAt) }

    override fun phone(phoneId: String): StoredPhone? = phones[phoneId]

    override fun putPhone(phone: StoredPhone) {
        phones[phone.phoneId] = phone
    }

    override fun phonesOf(accountId: String): List<StoredPhone> =
        phones.values.filter { it.accountId == accountId || it.pendingAccountId == accountId }.sortedBy { it.joinedAt }

    override fun activeDeviceKey(phoneId: String): StoredKey? =
        keys.values.firstOrNull { it.phoneId == phoneId && it.role == KeyRole.DEVICE && !it.isRevoked }

    override fun putLinkCode(code: StoredLinkCode) {
        linkCodes.values.removeAll { it.accountId == code.accountId }
        linkCodes[code.code] = code
    }

    override fun linkCode(code: String): StoredLinkCode? = linkCodes[code]

    override fun deleteLinkCode(code: String) {
        linkCodes.remove(code)
    }

    override fun appendAuditEntry(entry: AuditEntry) {
        audit += entry
    }

    override fun lastAuditEntry(): AuditEntry? = audit.lastOrNull()

    override fun auditEntries(): Sequence<AuditEntry> = audit.toList().asSequence()

    /** Lets a test change a stored entry the way someone with database access could. */
    fun replaceAuditEntry(entry: AuditEntry) {
        audit[audit.indexOfFirst { it.sequence == entry.sequence }] = entry
    }
}

package id.fatarc.trustgate.backend.store

import id.fatarc.trustgate.domain.api.Payment
import java.time.Instant

/** Keeps everything in memory, for tests and for running the backend inside one process. */
class InMemoryBackendStore : BackendStore {
    private val keys = HashMap<String, StoredKey>()
    private val stepUpKeys = HashMap<String, String>()
    private val challenges = HashMap<String, StoredChallenge>()
    private val spent = HashMap<String, Instant>()
    private val ledger = HashMap<Pair<String, String>, LedgerEntry>()

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

    override fun paymentsSince(deviceKeyId: String, since: Instant): List<Payment> = ledger
        .filterKeys { (device, _) -> device == deviceKeyId }
        .values
        .map { it.payment }
        .filter { !Instant.parse(it.processedAt).isBefore(since) }
        .sortedBy { Instant.parse(it.processedAt) }
}

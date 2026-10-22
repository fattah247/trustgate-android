package id.fatarc.trustgate.backend.audit

import id.fatarc.trustgate.backend.store.BackendStore
import id.fatarc.trustgate.domain.api.AuditStatus
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import java.time.Clock
import java.time.Instant

/** One record in the audit log. [hash] covers every other field and the previous entry's hash. */
class AuditEntry(
    val sequence: Long,
    val at: Instant,
    /** What happened, such as "payment-charged". */
    val event: String,
    /** Who or what it happened to, usually a phone's ID. */
    val subject: String,
    val detail: String,
    val previousHash: String,
    val hash: String,
)

/**
 * An append-only record of what the backend decided, where each entry's hash covers the one
 * before it. Changing, removing, or reordering any entry breaks every hash after it, so an edit
 * made straight to the database shows up when the chain is checked.
 *
 * The chain shows tampering; it can't stop someone who can rewrite the whole table and recompute
 * every hash. Copying [AuditStatus.headHash] somewhere they can't reach, as the server's own log
 * does at startup, is what makes that detectable too.
 */
class AuditLog(
    private val store: BackendStore,
    private val clock: Clock,
) {
    /** Appends an entry; call inside the transaction that made the change, so both land or neither does. */
    fun record(event: String, subject: String, detail: String = "") {
        val previous = store.lastAuditEntry()
        val sequence = (previous?.sequence ?: 0) + 1
        val at = clock.instant()
        val previousHash = previous?.hash ?: GENESIS
        store.appendAuditEntry(
            AuditEntry(sequence, at, event, subject, detail, previousHash, hashOf(sequence, at, event, subject, detail, previousHash)),
        )
    }

    /** Walks the chain from the first entry and reports the first one that doesn't follow. */
    fun verify(): AuditStatus {
        var previousHash = GENESIS
        var expectedSequence = 1L
        var count = 0L
        for (entry in store.auditEntries()) {
            val expected = hashOf(entry.sequence, entry.at, entry.event, entry.subject, entry.detail, previousHash)
            if (entry.sequence != expectedSequence || entry.previousHash != previousHash || entry.hash != expected) {
                return AuditStatus(intact = false, entries = count, headHash = previousHash.takeIf { count > 0 }, brokenAt = entry.sequence)
            }
            previousHash = entry.hash
            expectedSequence++
            count++
        }
        return AuditStatus(intact = true, entries = count, headHash = previousHash.takeIf { count > 0 })
    }

    companion object {
        const val GENESIS = "0000000000000000000000000000000000000000000000000000000000000000"

        fun hashOf(sequence: Long, at: Instant, event: String, subject: String, detail: String, previousHash: String): String =
            // Lengths before each field, so no choice of text can make two different entries hash alike.
            ReferenceSigningScheme.sha256Hex(
                listOf(sequence.toString(), at.toEpochMilli().toString(), event, subject, detail, previousHash)
                    .joinToString("") { "${it.length}:$it" },
            )
    }
}

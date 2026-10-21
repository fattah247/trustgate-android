package id.fatarc.trustgate.backend.audit

import id.fatarc.trustgate.backend.store.BackendStore
import id.fatarc.trustgate.domain.api.AuditStatus
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.time.Clock
import java.time.Duration
import java.time.Instant
import kotlinx.serialization.Serializable

/**
 * The audit log's head at one moment: its last entry and that entry's hash, signed by the
 * server's anchor key and, when a timestamping authority is set up, timestamped by it too.
 */
@Serializable
data class AuditCheckpoint(
    val sequence: Long,
    val hash: String,
    /** ISO-8601 instant the checkpoint was made. */
    val at: String,
    /** SHA-256 of the anchor key's public half, so a checkpoint names the key that must verify it. */
    val keyFingerprint: String,
    val signature: String,
    /** An RFC 3161 timestamp over [digest], Base64 DER, from an authority outside the server. */
    val timestampToken: String? = null,
) {
    val digest: ByteArray get() = digestOf(sequence, hash, at)

    companion object {
        fun digestOf(sequence: Long, hash: String, at: String): ByteArray = MessageDigest.getInstance("SHA-256")
            .digest(listOf("trustgate-audit-checkpoint", sequence.toString(), hash, at).joinToString("\n").toByteArray(StandardCharsets.UTF_8))
    }
}

/** Where checkpoints are kept: somewhere the database's owner can't quietly rewrite, such as write-once storage. */
interface CheckpointSink {
    fun append(checkpoint: AuditCheckpoint)

    fun all(): List<AuditCheckpoint>
}

/** An RFC 3161 timestamping authority: it signs that a digest existed at a time it vouches for. */
interface Timestamper {
    /** A token over [digest], Base64 DER, or null when the authority couldn't be reached. */
    fun timestamp(digest: ByteArray): String?

    /** When the authority says [token] was made, or null when it isn't a valid token over [digest]. */
    fun timeOf(token: String, digest: ByteArray): Instant?
}

/** How the checkpoints line up with the audit log as it is now. */
data class AnchorStatus(
    val checkpoints: Int,
    /** The first checkpoint the log no longer matches, or whose signature or timestamp doesn't hold. */
    val brokenAt: Long?,
    val problem: String?,
) {
    val intact: Boolean get() = brokenAt == null && problem == null
}

/**
 * Copies the audit log's head out of the database at intervals. The hash chain alone shows an
 * edited entry, but not a log rewritten from the start with every hash recomputed; a checkpoint
 * kept elsewhere, and timestamped by someone else, does. To pass, a rewrite would also have to
 * forge the anchor key's signature and a timestamp from before the rewrite.
 */
class AuditAnchoring(
    private val store: BackendStore,
    private val anchorKey: PrivateKey,
    private val anchorPublicKey: PublicKey,
    private val sink: CheckpointSink,
    private val timestamper: Timestamper? = null,
    private val clock: Clock = Clock.systemUTC(),
) {
    private val keyFingerprint = ReferenceSigningScheme.sha256Hex(anchorPublicKey.encoded)

    /**
     * Anchors the current head, unless nothing has been logged since the last checkpoint. Returns
     * the new checkpoint, or null when there was nothing new or the chain is already broken.
     */
    fun checkpoint(): AuditCheckpoint? {
        val head = store.transaction { AuditLog(store, clock).verify() }
        val headHash = head.headHash
        if (!head.intact || head.entries == 0L || headHash == null) return null
        if (sink.all().lastOrNull()?.sequence == head.entries) return null
        val at = clock.instant().toString()
        val digest = AuditCheckpoint.digestOf(head.entries, headHash, at)
        val signature = Signature.getInstance(ReferenceSigningScheme.SIGNATURE_ALGORITHM).run {
            initSign(anchorKey)
            update(digest)
            sign()
        }
        val checkpoint = AuditCheckpoint(
            sequence = head.entries,
            hash = headHash,
            at = at,
            keyFingerprint = keyFingerprint,
            signature = ReferenceSigningScheme.encode(signature),
            timestampToken = timestamper?.timestamp(digest),
        )
        sink.append(checkpoint)
        return checkpoint
    }

    /** The log's own chain check, failing too when the log no longer matches a checkpoint. */
    fun status(): AuditStatus {
        val chain = store.transaction { AuditLog(store, clock).verify() }
        val anchors = verify()
        return chain.copy(
            intact = chain.intact && anchors.intact,
            brokenAt = chain.brokenAt ?: anchors.brokenAt,
            checkpoints = anchors.checkpoints,
            checkpointProblem = anchors.problem,
        )
    }

    /** Checks every checkpoint's signature and timestamp, and that the log still has the hash it recorded. */
    fun verify(): AnchorStatus {
        val checkpoints = sink.all()
        if (checkpoints.isEmpty()) return AnchorStatus(0, null, null)
        val hashes = store.transaction { store.auditEntries().associate { it.sequence to it.hash } }
        for (checkpoint in checkpoints) {
            val problem = when {
                checkpoint.keyFingerprint != keyFingerprint -> "made with another anchor key"
                !signatureHolds(checkpoint) -> "its signature doesn't verify"
                hashes[checkpoint.sequence] == null -> "the log no longer reaches entry ${checkpoint.sequence}"
                hashes[checkpoint.sequence] != checkpoint.hash -> "the log's entry ${checkpoint.sequence} is no longer the one recorded"
                else -> timestampProblem(checkpoint)
            }
            if (problem != null) return AnchorStatus(checkpoints.size, checkpoint.sequence, "Checkpoint at entry ${checkpoint.sequence}: $problem.")
        }
        return AnchorStatus(checkpoints.size, null, null)
    }

    private fun signatureHolds(checkpoint: AuditCheckpoint): Boolean = runCatching {
        Signature.getInstance(ReferenceSigningScheme.SIGNATURE_ALGORITHM).run {
            initVerify(anchorPublicKey)
            update(checkpoint.digest)
            verify(checkNotNull(ReferenceSigningScheme.decodeOrNull(checkpoint.signature)))
        }
    }.getOrDefault(false)

    /** A timestamp must be valid, over this checkpoint, and from no earlier than the checkpoint says it was made. */
    private fun timestampProblem(checkpoint: AuditCheckpoint): String? {
        val token = checkpoint.timestampToken ?: return null
        val stamper = timestamper ?: return null
        val stamped = stamper.timeOf(token, checkpoint.digest) ?: return "its timestamp doesn't verify"
        val claimed = Instant.parse(checkpoint.at)
        return if (Duration.between(claimed, stamped).abs() > TIMESTAMP_TOLERANCE) "its timestamp is from another time" else null
    }

    private companion object {
        /** How far the authority's clock and ours may differ, network delay included. */
        val TIMESTAMP_TOLERANCE: Duration = Duration.ofMinutes(5)
    }
}

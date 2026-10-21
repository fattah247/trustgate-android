package id.fatarc.trustgate.backend

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.backend.audit.AuditAnchoring
import id.fatarc.trustgate.backend.audit.AuditCheckpoint
import id.fatarc.trustgate.backend.audit.AuditEntry
import id.fatarc.trustgate.backend.audit.AuditLog
import id.fatarc.trustgate.backend.audit.CheckpointSink
import id.fatarc.trustgate.backend.audit.Timestamper
import id.fatarc.trustgate.backend.store.InMemoryBackendStore
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.testing.MutableClock
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.developmentPolicy
import id.fatarc.trustgate.testing.selfSignedChain
import java.time.Instant
import java.util.Base64
import org.junit.Test

class AuditAnchoringTest {
    private val clock = MutableClock()
    private val store = InMemoryBackendStore()
    private val backend = ReferenceBackend(developmentPolicy, clock, store = store)
    private val anchorKey = TestKey()
    private val sink = object : CheckpointSink {
        val kept = mutableListOf<AuditCheckpoint>()

        override fun append(checkpoint: AuditCheckpoint) {
            kept += checkpoint
        }

        override fun all(): List<AuditCheckpoint> = kept.toList()
    }

    /** Stands in for an outside authority: it remembers when it stamped each digest. */
    private val timestamper = object : Timestamper {
        val stamped = mutableMapOf<String, Instant>()

        override fun timestamp(digest: ByteArray): String = Base64.getEncoder().encodeToString(digest).also { stamped[it] = clock.now }

        override fun timeOf(token: String, digest: ByteArray): Instant? =
            stamped[token]?.takeIf { token == Base64.getEncoder().encodeToString(digest) }
    }

    private fun anchoring(key: TestKey = anchorKey) = AuditAnchoring(store, key.pair.private, key.pair.public, sink, timestamper, clock)

    private fun logSomething() {
        val key = TestKey()
        val challenge = backend.issueRegistrationChallenge()
        backend.registerKey(KeyRole.DEVICE, key.encodedPublicKey, selfSignedChain(key), challenge)
    }

    @Test
    fun `checkpoints of an untouched log all hold`() {
        logSomething()
        anchoring().checkpoint()
        logSomething()
        anchoring().checkpoint()

        val status = anchoring().verify()

        assertThat(status.checkpoints).isEqualTo(2)
        assertThat(status.intact).isTrue()
    }

    @Test
    fun `nothing new since the last checkpoint makes no new one`() {
        logSomething()
        anchoring().checkpoint()

        assertThat(anchoring().checkpoint()).isNull()
        assertThat(sink.kept).hasSize(1)
    }

    @Test
    fun `a log rewritten from the start with every hash recomputed still contradicts its checkpoint`() {
        logSomething()
        logSomething()
        anchoring().checkpoint()

        // Someone with the database rewrites the first entry and rebuilds the whole chain to match.
        var previous = AuditLog.GENESIS
        store.auditEntries().toList().forEach { entry ->
            val detail = if (entry.sequence == 1L) "nothing happened" else entry.detail
            val hash = AuditLog.hashOf(entry.sequence, entry.at, entry.event, entry.subject, detail, previous)
            store.replaceAuditEntry(AuditEntry(entry.sequence, entry.at, entry.event, entry.subject, detail, previous, hash))
            previous = hash
        }

        assertThat(backend.auditStatus().intact).isTrue()
        assertThat(anchoring().verify().brokenAt).isEqualTo(2)
        assertThat(anchoring().status().intact).isFalse()
        assertThat(anchoring().status().checkpointProblem).contains("no longer the one recorded")
    }

    @Test
    fun `a checkpoint signed by another key, or with a changed hash, doesn't count`() {
        logSomething()
        anchoring(key = TestKey()).checkpoint()

        assertThat(anchoring().verify().problem).contains("another anchor key")

        sink.kept.clear()
        anchoring().checkpoint()
        sink.kept[0] = sink.kept[0].copy(hash = "0".repeat(64))
        assertThat(anchoring().verify().problem).contains("signature")
    }

    @Test
    fun `a checkpoint whose outside timestamp is from another time is caught`() {
        logSomething()
        val checkpoint = checkNotNull(anchoring().checkpoint())
        // Claimed to be made an hour before the authority actually stamped it.
        timestamper.stamped[checkNotNull(checkpoint.timestampToken)] = clock.now.plusSeconds(3600)

        assertThat(anchoring().verify().problem).contains("timestamp")
    }
}

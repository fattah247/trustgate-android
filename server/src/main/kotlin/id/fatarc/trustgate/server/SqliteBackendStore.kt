package id.fatarc.trustgate.server

import id.fatarc.trustgate.backend.audit.AuditEntry
import id.fatarc.trustgate.backend.store.BackendStore
import id.fatarc.trustgate.backend.store.ChallengePurpose
import id.fatarc.trustgate.backend.store.LedgerEntry
import id.fatarc.trustgate.backend.store.StoredChallenge
import id.fatarc.trustgate.backend.store.StoredKey
import id.fatarc.trustgate.domain.api.Payment
import id.fatarc.trustgate.domain.api.RequiredConfirmation
import id.fatarc.trustgate.domain.api.TrustGateJson
import id.fatarc.trustgate.domain.signing.KeyRole
import java.io.File
import java.sql.Connection
import java.sql.DriverManager
import java.sql.ResultSet
import java.time.Instant

/** The backend's state in one SQLite file. Instants are stored as epoch milliseconds so they compare correctly. */
class SqliteBackendStore(file: File) : BackendStore, AutoCloseable {
    private val connection: Connection = DriverManager.getConnection("jdbc:sqlite:${file.path}")
    private var depth = 0

    init {
        connection.createStatement().use { statement ->
            statement.execute("PRAGMA journal_mode=WAL")
            SCHEMA.forEach(statement::execute)
        }
        connection.autoCommit = false
        migrate()
        connection.commit()
    }

    /** Brings a database written by an older server up to date, one numbered step at a time. */
    private fun migrate() {
        val version = query("PRAGMA user_version") { it.getInt(1) } ?: 0
        MIGRATIONS.drop(version).forEach { step -> step(this) }
        connection.createStatement().use { it.execute("PRAGMA user_version = ${MIGRATIONS.size}") }
    }

    /** Version 1: when and how much each payment charged, indexed, so limits don't read the whole ledger. */
    private fun addLedgerTimes() {
        update("ALTER TABLE ledger ADD COLUMN charged_at INTEGER NOT NULL DEFAULT 0")
        update("ALTER TABLE ledger ADD COLUMN amount_minor INTEGER NOT NULL DEFAULT 0")
        val rows = connection.prepareStatement("SELECT device_key_id, idempotency_key, payment FROM ledger").use { statement ->
            statement.executeQuery().use { rows ->
                buildList { while (rows.next()) add(Triple(rows.getString(1), rows.getString(2), rows.getString(3))) }
            }
        }
        rows.forEach { (device, idempotencyKey, json) ->
            val payment = TrustGateJson.decodeFromString(Payment.serializer(), json)
            update(
                "UPDATE ledger SET charged_at = ?, amount_minor = ? WHERE device_key_id = ? AND idempotency_key = ?",
                Instant.parse(payment.processedAt).toEpochMilli(), payment.amountMinor, device, idempotencyKey,
            )
        }
        update("CREATE INDEX IF NOT EXISTS ledger_by_device_time ON ledger (device_key_id, charged_at)")
    }

    /**
     * Version 2: which phone each key belongs to, when that phone enrolled, and revocation; plus
     * the hash-chained audit log. Keys from before belong to the phone of their device key.
     */
    private fun addKeyLifecycleAndAudit() {
        update("ALTER TABLE keys ADD COLUMN phone_id TEXT NOT NULL DEFAULT ''")
        update("ALTER TABLE keys ADD COLUMN phone_enrolled_at INTEGER NOT NULL DEFAULT 0")
        update("ALTER TABLE keys ADD COLUMN revoked_at INTEGER")
        update("ALTER TABLE keys ADD COLUMN revoked_reason TEXT")
        update("UPDATE keys SET phone_id = device_key_id")
        update(
            "UPDATE keys SET phone_enrolled_at = " +
                "(SELECT owner.registered_at FROM keys AS owner WHERE owner.key_id = keys.device_key_id)",
        )
        update("CREATE INDEX IF NOT EXISTS keys_by_phone ON keys (phone_id)")
        update(
            """CREATE TABLE IF NOT EXISTS audit_log (
                sequence INTEGER PRIMARY KEY, at INTEGER NOT NULL, event TEXT NOT NULL, subject TEXT NOT NULL,
                detail TEXT NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL)""",
        )
    }

    @Synchronized
    override fun <T> transaction(block: () -> T): T {
        if (depth > 0) return block()
        depth++
        try {
            return block().also { connection.commit() }
        } catch (error: Throwable) {
            connection.rollback()
            throw error
        } finally {
            depth--
        }
    }

    override fun key(keyId: String): StoredKey? = query("SELECT * FROM keys WHERE key_id = ?", keyId) { row ->
        StoredKey(
            keyId = row.getString("key_id"),
            role = KeyRole.valueOf(row.getString("role")),
            encodedPublicKey = row.getBytes("public_key"),
            deviceKeyId = row.getString("device_key_id"),
            attested = row.getBoolean("attested"),
            rootKeyFingerprint = row.getString("root_fingerprint"),
            registeredAt = Instant.ofEpochMilli(row.getLong("registered_at")),
            phoneId = row.getString("phone_id"),
            phoneEnrolledAt = Instant.ofEpochMilli(row.getLong("phone_enrolled_at")),
            revokedAt = row.getLong("revoked_at").takeUnless { row.wasNull() }?.let(Instant::ofEpochMilli),
            revokedReason = row.getString("revoked_reason"),
        )
    }

    override fun putKey(key: StoredKey) = update(
        "INSERT OR REPLACE INTO keys (key_id, role, public_key, device_key_id, attested, root_fingerprint, registered_at, " +
            "phone_id, phone_enrolled_at, revoked_at, revoked_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        key.keyId, key.role.name, key.encodedPublicKey, key.deviceKeyId, key.attested, key.rootKeyFingerprint, key.registeredAt.toEpochMilli(),
        key.phoneId, key.phoneEnrolledAt.toEpochMilli(), key.revokedAt?.toEpochMilli(), key.revokedReason,
    )

    override fun deleteKey(keyId: String) = update("DELETE FROM keys WHERE key_id = ?", keyId)

    override fun stepUpKeyOf(deviceKeyId: String): String? =
        query("SELECT key_id FROM step_up_keys WHERE device_key_id = ?", deviceKeyId) { it.getString(1) }

    override fun setStepUpKey(deviceKeyId: String, keyId: String?) {
        if (keyId == null) {
            update("DELETE FROM step_up_keys WHERE device_key_id = ?", deviceKeyId)
        } else {
            update("INSERT OR REPLACE INTO step_up_keys VALUES (?, ?)", deviceKeyId, keyId)
        }
    }

    override fun putChallenge(challenge: StoredChallenge) = update(
        "INSERT INTO challenges VALUES (?, ?, ?, ?, ?)",
        challenge.nonce, challenge.purpose.name, challenge.deviceKeyId, challenge.confirmation.name, challenge.expiresAt.toEpochMilli(),
    )

    override fun challenge(nonce: String): StoredChallenge? = query("SELECT * FROM challenges WHERE nonce = ?", nonce) { row ->
        StoredChallenge(
            nonce = row.getString("nonce"),
            purpose = ChallengePurpose.valueOf(row.getString("purpose")),
            deviceKeyId = row.getString("device_key_id"),
            confirmation = RequiredConfirmation.valueOf(row.getString("confirmation")),
            expiresAt = Instant.ofEpochMilli(row.getLong("expires_at")),
        )
    }

    override fun spendChallenge(nonce: String, at: Instant) {
        update("DELETE FROM challenges WHERE nonce = ?", nonce)
        update("INSERT OR REPLACE INTO spent_nonces VALUES (?, ?)", nonce, at.toEpochMilli())
    }

    override fun isSpent(nonce: String): Boolean = query("SELECT 1 FROM spent_nonces WHERE nonce = ?", nonce) { true } ?: false

    override fun prune(challengesExpiredBefore: Instant, spentBefore: Instant) {
        update("DELETE FROM challenges WHERE expires_at < ?", challengesExpiredBefore.toEpochMilli())
        update("DELETE FROM spent_nonces WHERE spent_at < ?", spentBefore.toEpochMilli())
    }

    override fun ledgerEntry(deviceKeyId: String, idempotencyKey: String): LedgerEntry? = query(
        "SELECT fingerprint, payment FROM ledger WHERE device_key_id = ? AND idempotency_key = ?",
        deviceKeyId,
        idempotencyKey,
    ) { row -> LedgerEntry(row.getString(1), TrustGateJson.decodeFromString(Payment.serializer(), row.getString(2))) }

    override fun putLedgerEntry(deviceKeyId: String, idempotencyKey: String, entry: LedgerEntry) = update(
        "INSERT INTO ledger (device_key_id, idempotency_key, fingerprint, payment, charged_at, amount_minor) VALUES (?, ?, ?, ?, ?, ?)",
        deviceKeyId,
        idempotencyKey,
        entry.fingerprint,
        TrustGateJson.encodeToString(Payment.serializer(), entry.payment),
        Instant.parse(entry.payment.processedAt).toEpochMilli(),
        entry.payment.amountMinor,
    )

    override fun ledgerSize(): Int = query("SELECT COUNT(*) FROM ledger") { it.getInt(1) } ?: 0

    override fun paymentsSince(phoneId: String, since: Instant): List<Payment> =
        connection.prepareStatement(
            "SELECT payment FROM ledger WHERE device_key_id IN (SELECT key_id FROM keys WHERE phone_id = ?) AND charged_at >= ? ORDER BY charged_at",
        ).use { statement ->
            statement.setString(1, phoneId)
            statement.setLong(2, since.toEpochMilli())
            statement.executeQuery().use { rows ->
                buildList { while (rows.next()) add(TrustGateJson.decodeFromString(Payment.serializer(), rows.getString(1))) }
            }
        }

    override fun appendAuditEntry(entry: AuditEntry) = update(
        "INSERT INTO audit_log VALUES (?, ?, ?, ?, ?, ?, ?)",
        entry.sequence, entry.at.toEpochMilli(), entry.event, entry.subject, entry.detail, entry.previousHash, entry.hash,
    )

    override fun lastAuditEntry(): AuditEntry? = query("SELECT * FROM audit_log ORDER BY sequence DESC LIMIT 1") { it.auditEntry() }

    override fun auditEntries(): Sequence<AuditEntry> = sequence {
        // In pages, so checking a long log doesn't hold it all in memory.
        var after = 0L
        while (true) {
            val page = connection.prepareStatement("SELECT * FROM audit_log WHERE sequence > ? ORDER BY sequence LIMIT 500").use { statement ->
                statement.setLong(1, after)
                statement.executeQuery().use { rows -> buildList { while (rows.next()) add(rows.auditEntry()) } }
            }
            if (page.isEmpty()) break
            yieldAll(page)
            after = page.last().sequence
        }
    }

    private fun ResultSet.auditEntry() = AuditEntry(
        sequence = getLong("sequence"),
        at = Instant.ofEpochMilli(getLong("at")),
        event = getString("event"),
        subject = getString("subject"),
        detail = getString("detail"),
        previousHash = getString("previous_hash"),
        hash = getString("hash"),
    )

    /** Lets a test change a stored entry the way someone with database access could. */
    internal fun overwriteAuditDetail(sequence: Long, detail: String) = update("UPDATE audit_log SET detail = ? WHERE sequence = ?", detail, sequence)

    override fun close() = connection.close()

    private fun <T> query(sql: String, vararg parameters: Any?, read: (ResultSet) -> T): T? =
        connection.prepareStatement(sql).use { statement ->
            parameters.forEachIndexed { index, value -> statement.setObject(index + 1, value) }
            statement.executeQuery().use { rows -> if (rows.next()) read(rows) else null }
        }

    private fun update(sql: String, vararg parameters: Any?) {
        connection.prepareStatement(sql).use { statement ->
            parameters.forEachIndexed { index, value -> statement.setObject(index + 1, value) }
            statement.executeUpdate()
        }
    }

    private companion object {
        /** Each step after the original schema, in order; the database's user_version counts those applied. */
        val MIGRATIONS: List<(SqliteBackendStore) -> Unit> = listOf(
            SqliteBackendStore::addLedgerTimes,
            SqliteBackendStore::addKeyLifecycleAndAudit,
        )

        /** The original schema; [MIGRATIONS] build on it. */
        val SCHEMA = listOf(
            """CREATE TABLE IF NOT EXISTS keys (
                key_id TEXT PRIMARY KEY, role TEXT NOT NULL, public_key BLOB NOT NULL, device_key_id TEXT NOT NULL,
                attested INTEGER NOT NULL, root_fingerprint TEXT, registered_at INTEGER NOT NULL)""",
            "CREATE TABLE IF NOT EXISTS step_up_keys (device_key_id TEXT PRIMARY KEY, key_id TEXT NOT NULL)",
            """CREATE TABLE IF NOT EXISTS challenges (
                nonce TEXT PRIMARY KEY, purpose TEXT NOT NULL, device_key_id TEXT, confirmation TEXT NOT NULL, expires_at INTEGER NOT NULL)""",
            "CREATE TABLE IF NOT EXISTS spent_nonces (nonce TEXT PRIMARY KEY, spent_at INTEGER NOT NULL)",
            """CREATE TABLE IF NOT EXISTS ledger (
                device_key_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, fingerprint TEXT NOT NULL, payment TEXT NOT NULL,
                PRIMARY KEY (device_key_id, idempotency_key))""",
        )
    }
}

package id.fatarc.trustgate.server

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
        connection.commit()
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
        )
    }

    override fun putKey(key: StoredKey) = update(
        "INSERT OR REPLACE INTO keys VALUES (?, ?, ?, ?, ?, ?, ?)",
        key.keyId, key.role.name, key.encodedPublicKey, key.deviceKeyId, key.attested, key.rootKeyFingerprint, key.registeredAt.toEpochMilli(),
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
        "INSERT INTO ledger VALUES (?, ?, ?, ?)",
        deviceKeyId, idempotencyKey, entry.fingerprint, TrustGateJson.encodeToString(Payment.serializer(), entry.payment),
    )

    override fun ledgerSize(): Int = query("SELECT COUNT(*) FROM ledger") { it.getInt(1) } ?: 0

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

package id.fatarc.trustgate.server

import id.fatarc.trustgate.backend.ReferenceBackend
import id.fatarc.trustgate.backend.audit.AuditAnchoring
import id.fatarc.trustgate.backend.integrity.DeviceRecallWriter
import id.fatarc.trustgate.domain.api.ServerHealth
import io.ktor.server.engine.applicationEngineEnvironment
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.sslConnector
import io.ktor.server.netty.Netty
import java.io.File
import java.security.KeyStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory

fun main() {
    val config = ServerConfig.fromEnvironment()
    val store = SqliteBackendStore(config.database)
    val revocations = RevocationCache(config.revocationUrl, File(config.database.absoluteFile.parentFile, "attestation-status.json"))
    val integrity = config.playIntegrityCredentials?.let { PlayIntegrityVerifier(config.packageName, it) }
    val recallWriter = config.playIntegrityCredentials?.takeIf { config.deviceRecall }
        ?.let { PlayDeviceRecallWriter(config.packageName, it) }
        ?: DeviceRecallWriter.NONE
    val backend = ReferenceBackend(
        policy = config.policy(integrity),
        revocations = revocations::current,
        store = store,
        recallWriter = recallWriter,
    )
    val anchoring = config.anchorKeystore?.let { keystore ->
        val key = loadAnchorKey(keystore, checkNotNull(config.anchorPassword))
        AuditAnchoring(
            store = store,
            anchorKey = key.private,
            anchorPublicKey = key.public,
            sink = FileCheckpointSink(config.checkpointFile ?: File(config.database.absoluteFile.parentFile, "audit-checkpoints.jsonl")),
            timestamper = config.timestampUrl?.let { Rfc3161Timestamper.overHttp(it, config.timestampCertificates) },
        )
    }
    val password = config.keystorePassword.toCharArray()
    val keyStore = KeyStore.getInstance(config.keystore, password)
    val log = LoggerFactory.getLogger("trustgate")
    log.info("Enforcing the {} policy for {}.", config.policyName, config.packageName)
    if (config.policyName == ServerConfig.STRICT && integrity == null) {
        log.warn("No Play Integrity credentials: every integrity token will count as unverifiable.")
    }
    // The head hash goes to the server's own log too, outside the database, so a rewrite of the
    // whole audit table would no longer match what was logged here.
    val audit = anchoring?.status() ?: backend.auditStatus()
    when {
        audit.intact -> log.info("Audit log intact: {} entries, head {}, {} checkpoints.", audit.entries, audit.headHash ?: "none", audit.checkpoints)
        audit.checkpointProblem != null -> log.error("Audit log doesn't match its checkpoints. {}", audit.checkpointProblem)
        else -> log.error("Audit log broken at entry {}: an entry was changed, removed, or reordered.", audit.brokenAt)
    }
    if (anchoring == null) log.warn("No audit anchor key: the audit log isn't checkpointed outside the database.")
    if (config.adminToken == null) log.info("No admin token: the /admin routes are off.")

    val environment = applicationEngineEnvironment {
        this.log = log
        // HTTPS only; there is no plain HTTP connector to fall back to.
        sslConnector(keyStore = keyStore, keyAlias = "trustgate", keyStorePassword = { password }, privateKeyPassword = { password }) {
            host = config.host
            port = config.port
            keyStorePath = config.keystore
        }
        module {
            revocations.startRefreshing(this)
            anchoring?.let { anchors ->
                launch(Dispatchers.IO) {
                    while (isActive) {
                        runCatching { anchors.checkpoint() }
                            .onSuccess { made -> made?.let { log.info("Checkpointed the audit log at entry {}.", it.sequence) } }
                            .onFailure { log.warn("Couldn't checkpoint the audit log: {}", it.message) }
                        delay(config.checkpointEvery.toMillis())
                    }
                }
            }
            trustGateModule(backend, ServerHealth(status = "ok", policy = config.policyName), adminToken = config.adminToken, anchoring = anchoring)
        }
    }
    embeddedServer(Netty, environment).start(wait = true)
}

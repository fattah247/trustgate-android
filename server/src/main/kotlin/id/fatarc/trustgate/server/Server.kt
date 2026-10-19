package id.fatarc.trustgate.server

import id.fatarc.trustgate.backend.ReferenceBackend
import id.fatarc.trustgate.domain.api.ServerHealth
import io.ktor.server.engine.applicationEngineEnvironment
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.sslConnector
import io.ktor.server.netty.Netty
import java.io.File
import java.security.KeyStore
import org.slf4j.LoggerFactory

fun main() {
    val config = ServerConfig.fromEnvironment()
    val store = SqliteBackendStore(config.database)
    val revocations = RevocationCache(config.revocationUrl, File(config.database.absoluteFile.parentFile, "attestation-status.json"))
    val backend = ReferenceBackend(policy = config.policy(), revocations = revocations::current, store = store)
    val password = config.keystorePassword.toCharArray()
    val keyStore = KeyStore.getInstance(config.keystore, password)
    val log = LoggerFactory.getLogger("trustgate")
    log.info("Enforcing the {} attestation policy for {}.", config.policyName, config.packageName)

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
            trustGateModule(backend, ServerHealth(status = "ok", policy = config.policyName))
        }
    }
    embeddedServer(Netty, environment).start(wait = true)
}

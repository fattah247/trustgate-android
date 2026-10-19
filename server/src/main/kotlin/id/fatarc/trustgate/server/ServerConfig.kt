package id.fatarc.trustgate.server

import id.fatarc.trustgate.backend.BackendPolicy
import id.fatarc.trustgate.backend.attestation.RevocationList
import id.fatarc.trustgate.backend.integrity.IntegrityVerifier
import java.io.File

/** Read from the environment. With no policy named the server enforces [BackendPolicy.strict]. */
class ServerConfig(
    val host: String,
    val port: Int,
    val keystore: File,
    val keystorePassword: String,
    val database: File,
    val policyName: String,
    val packageName: String,
    val signingCertificateDigests: Set<String>,
    val minimumOsPatchLevel: Int?,
    /** Where Google's status list is fetched from; null turns fetching off. */
    val revocationUrl: String?,
    /** A Google service account allowed to decode this app's Play Integrity tokens. */
    val playIntegrityCredentials: File?,
) {
    fun policy(integrity: IntegrityVerifier?): BackendPolicy = when (policyName) {
        STRICT -> BackendPolicy.strict(packageName, signingCertificateDigests, integrity, minimumOsPatchLevel)
        DEVELOPMENT -> BackendPolicy.development(packageName, signingCertificateDigests)
        else -> error("Unknown policy \"$policyName\"; use $STRICT or $DEVELOPMENT.")
    }

    companion object {
        const val STRICT = "strict"
        const val DEVELOPMENT = "development"

        fun fromEnvironment(env: Map<String, String> = System.getenv()): ServerConfig {
            fun required(name: String) = env[name]?.takeIf { it.isNotBlank() } ?: error("$name must be set.")
            return ServerConfig(
                // Loopback only: the emulator reaches it as 10.0.2.2, and nothing else on the network can.
                host = env["TRUSTGATE_HOST"] ?: "127.0.0.1",
                port = env["TRUSTGATE_PORT"]?.toInt() ?: 8443,
                keystore = File(required("TRUSTGATE_TLS_KEYSTORE")),
                keystorePassword = File(required("TRUSTGATE_TLS_PASSWORD_FILE")).readText().trim(),
                database = File(env["TRUSTGATE_DATABASE"] ?: "trustgate.db"),
                policyName = env["TRUSTGATE_POLICY"] ?: STRICT,
                packageName = required("TRUSTGATE_PACKAGE"),
                signingCertificateDigests = env["TRUSTGATE_SIGNING_DIGESTS"].orEmpty()
                    .split(',').map { it.trim().lowercase() }.filter { it.isNotEmpty() }.toSet(),
                minimumOsPatchLevel = env["TRUSTGATE_MIN_PATCH_LEVEL"]?.toInt(),
                revocationUrl = env["TRUSTGATE_REVOCATION_URL"].let { if (it == "off") null else it ?: RevocationList.URL },
                playIntegrityCredentials = env["TRUSTGATE_PLAY_INTEGRITY_CREDENTIALS"]?.let(::File),
            )
        }
    }
}

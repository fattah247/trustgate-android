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
    /** The oldest app version code the server serves; older versions are told to update. */
    val minimumAppVersionCode: Long?,
    /** Whether a phone without Play's strong integrity has to confirm each payment. */
    val requireStrongIntegrity: Boolean,
    /** Where Google's status list is fetched from; null turns fetching off. */
    val revocationUrl: String?,
    /** A Google service account allowed to decode this app's Play Integrity tokens. */
    val playIntegrityCredentials: File?,
    /** The bearer token the /admin routes require; without one they aren't served at all. */
    val adminToken: String? = null,
    /** Write device recall bits; needs Play Integrity credentials and device recall turned on in Play Console. */
    val deviceRecall: Boolean = false,
    /** The PKCS#12 key that signs audit checkpoints, and its password; without it there are no checkpoints. */
    val anchorKeystore: File? = null,
    val anchorPassword: String? = null,
    /** Where checkpoints are appended; somewhere the database's owner can't rewrite. */
    val checkpointFile: File? = null,
    val checkpointEvery: java.time.Duration = java.time.Duration.ofMinutes(10),
    /** An RFC 3161 timestamping authority for checkpoints, and the SHA-256 of each signing certificate of its to trust. */
    val timestampUrl: String? = null,
    val timestampCertificates: Set<String> = emptySet(),
) {
    fun policy(integrity: IntegrityVerifier?): BackendPolicy = when (policyName) {
        STRICT -> BackendPolicy.strict(
            packageName = packageName,
            signingCertificateDigests = signingCertificateDigests,
            integrity = integrity,
            minimumOsPatchLevel = minimumOsPatchLevel,
            minimumAppVersionCode = minimumAppVersionCode,
            requireStrongIntegrity = requireStrongIntegrity,
        )
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
                minimumAppVersionCode = env["TRUSTGATE_MIN_APP_VERSION"]?.toLong(),
                requireStrongIntegrity = env["TRUSTGATE_REQUIRE_STRONG_INTEGRITY"]?.toBooleanStrict() ?: true,
                revocationUrl = env["TRUSTGATE_REVOCATION_URL"].let { if (it == "off") null else it ?: RevocationList.URL },
                playIntegrityCredentials = env["TRUSTGATE_PLAY_INTEGRITY_CREDENTIALS"]?.let(::File),
                deviceRecall = env["TRUSTGATE_DEVICE_RECALL"] == "on",
                anchorKeystore = env["TRUSTGATE_ANCHOR_KEYSTORE"]?.let(::File),
                anchorPassword = env["TRUSTGATE_ANCHOR_PASSWORD_FILE"]?.let { File(it).readText().trim() },
                checkpointFile = env["TRUSTGATE_CHECKPOINTS"]?.let(::File),
                checkpointEvery = env["TRUSTGATE_CHECKPOINT_MINUTES"]?.toLong()?.let(java.time.Duration::ofMinutes) ?: java.time.Duration.ofMinutes(10),
                timestampUrl = env["TRUSTGATE_TSA_URL"],
                timestampCertificates = env["TRUSTGATE_TSA_CERT_SHA256"].orEmpty()
                    .split(',').map { it.trim().lowercase() }.filter { it.isNotEmpty() }.toSet(),
                adminToken = env["TRUSTGATE_ADMIN_TOKEN_FILE"]?.let { File(it).readText().trim() }?.also { token ->
                    require(token.length >= 32) { "The admin token must be at least 32 characters." }
                },
            ).also {
                // Without a pinned certificate, anyone could make a timestamp that verifies.
                require(it.timestampUrl == null || it.timestampCertificates.isNotEmpty()) { "TRUSTGATE_TSA_CERT_SHA256 must be set with TRUSTGATE_TSA_URL." }
                require(it.anchorKeystore == null || it.anchorPassword != null) { "TRUSTGATE_ANCHOR_PASSWORD_FILE must be set with TRUSTGATE_ANCHOR_KEYSTORE." }
            }
        }
    }
}

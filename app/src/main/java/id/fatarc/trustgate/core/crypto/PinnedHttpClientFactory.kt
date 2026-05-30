package id.fatarc.trustgate.core.crypto

import okhttp3.CertificatePinner
import okhttp3.OkHttpClient

data class PinningConfig(
    val enabled: Boolean = false,
    val host: String = "publicobject.com",
    val pins: List<String> = listOf(
        "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    ),
)

class PinnedHttpClientFactory {
    fun create(config: PinningConfig = PinningConfig()): OkHttpClient {
        return OkHttpClient.Builder().apply {
            if (config.enabled && config.pins.isNotEmpty()) {
                certificatePinner(
                    CertificatePinner.Builder().add(config.host, *config.pins.toTypedArray()).build(),
                )
            }
        }.build()
    }
}


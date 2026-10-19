package id.fatarc.trustgate.server

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class PlayIntegrityVerifierTest {
    // The shape of a decodeIntegrityToken response, trimmed to the fields the backend reads and one it ignores.
    private val response = """
        {
          "tokenPayloadExternal": {
            "requestDetails": {"requestPackageName": "id.fatarc.trustgate", "requestHash": "abc123", "timestampMillis": "1760000000000"},
            "appIntegrity": {
              "appRecognitionVerdict": "PLAY_RECOGNIZED",
              "packageName": "id.fatarc.trustgate",
              "certificateSha256Digest": ["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"],
              "versionCode": "1"
            },
            "deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"]},
            "accountDetails": {"appLicensingVerdict": "LICENSED"}
          }
        }
    """

    @Test
    fun `a decoded verdict keeps the request binding, app, certificate, and device labels`() {
        val verdict = PlayIntegrityVerifier.verdictFrom(response)

        assertThat(verdict.requestPackageName).isEqualTo("id.fatarc.trustgate")
        assertThat(verdict.requestHash).isEqualTo("abc123")
        assertThat(verdict.timestampMillis).isEqualTo(1_760_000_000_000)
        assertThat(verdict.appRecognition).isEqualTo("PLAY_RECOGNIZED")
        assertThat(verdict.certificateDigests).containsExactly((0..31).joinToString("") { "%02x".format(it) })
        assertThat(verdict.deviceRecognition).containsExactly("MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY")
        assertThat(verdict.mock).isFalse()
    }
}

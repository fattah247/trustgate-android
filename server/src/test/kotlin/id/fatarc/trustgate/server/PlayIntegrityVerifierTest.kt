package id.fatarc.trustgate.server

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.domain.api.RecallBit
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
        assertThat(verdict.appVersionCode).isEqualTo(1)
        assertThat(verdict.appLicensing).isEqualTo("LICENSED")
    }

    @Test
    fun `the optional verdicts are read when Play Console turns them on, and left unknown when it doesn't`() {
        val withOptional = PlayIntegrityVerifier.verdictFrom(
            """
            {
              "tokenPayloadExternal": {
                "requestDetails": {"requestPackageName": "id.fatarc.trustgate", "requestHash": "abc123", "timestampMillis": "1760000000000"},
                "deviceIntegrity": {
                  "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"],
                  "recentDeviceActivity": {"deviceActivityLevel": "LEVEL_4"}
                },
                "environmentDetails": {
                  "playProtectVerdict": "POSSIBLE_RISK",
                  "appAccessRiskVerdict": {"appsDetected": ["KNOWN_INSTALLED", "UNKNOWN_CONTROLLING"]}
                }
              }
            }
            """,
        )
        val without = PlayIntegrityVerifier.verdictFrom(response)

        assertThat(withOptional.appsDetected).containsExactly("KNOWN_INSTALLED", "UNKNOWN_CONTROLLING")
        assertThat(withOptional.playProtect).isEqualTo("POSSIBLE_RISK")
        assertThat(withOptional.deviceActivity).isEqualTo("LEVEL_4")
        assertThat(without.appsDetected).isNull()
        assertThat(without.playProtect).isNull()
        assertThat(without.deviceActivity).isNull()
    }

    @Test
    fun `device recall bits are read when device recall is on`() {
        val verdict = PlayIntegrityVerifier.verdictFrom(
            """
            {
              "tokenPayloadExternal": {
                "requestDetails": {"requestPackageName": "id.fatarc.trustgate", "requestHash": "abc123", "timestampMillis": "1760000000000"},
                "deviceIntegrity": {
                  "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"],
                  "deviceRecall": {"values": {"bitFirst": true, "bitSecond": false, "bitThird": true}, "writeDates": {"yyyymmFirst": 202601, "yyyymmThird": 202510}}
                }
              }
            }
            """,
        )

        assertThat(verdict.deviceRecall).containsExactly(RecallBit.FIRST, RecallBit.THIRD)
        assertThat(PlayIntegrityVerifier.verdictFrom(response).deviceRecall).isNull()
    }

    @Test
    fun `a device recall write sends only the bits being changed`() {
        assertThat(PlayDeviceRecallWriter.body("token-1", mapOf(RecallBit.SECOND to true)))
            .isEqualTo("""{"integrityToken":"token-1","newValues":{"bitSecond":true}}""")
    }
}

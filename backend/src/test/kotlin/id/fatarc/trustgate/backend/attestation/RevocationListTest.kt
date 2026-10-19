package id.fatarc.trustgate.backend.attestation

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class RevocationListTest {
    // The example from Google's documentation of the status list.
    private val document = """
        {
          "entries": {
            "2c8cdddfd5e03bfc": {"status": "REVOKED", "expires": "2020-11-13", "reason": "KEY_COMPROMISE", "comment": "Key stored on unsecure system"},
            "c8966fcb2fbb0d7a": {"status": "SUSPENDED", "reason": "SOFTWARE_FLAW", "comment": "Bug in keystore causes this key malfunction b/555555"}
          }
        }
    """

    @Test
    fun `revoked and suspended certificates are both listed`() {
        val list = RevocationList.parse(document)

        assertThat(list.statusOf("2c8cdddfd5e03bfc")?.status).isEqualTo("REVOKED")
        assertThat(list.statusOf("c8966fcb2fbb0d7a")?.reason).isEqualTo("SOFTWARE_FLAW")
        assertThat(list.statusOf("1")).isNull()
    }
}

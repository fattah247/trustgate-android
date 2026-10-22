package id.fatarc.trustgate.backend.attestation

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class GoogleAttestationRootsTest {
    @Test
    fun `every bundled root is intact and signs itself`() {
        // A single wrong character in a copied certificate breaks its own signature.
        GoogleAttestationRoots.certificates.forEach { root -> root.verify(root.publicKey) }

        assertThat(GoogleAttestationRoots.certificates).hasSize(5)
    }

    @Test
    fun `the rotated RSA roots share one key, beside the ECDSA root`() {
        assertThat(GoogleAttestationRoots.keyFingerprints).hasSize(2)
    }
}

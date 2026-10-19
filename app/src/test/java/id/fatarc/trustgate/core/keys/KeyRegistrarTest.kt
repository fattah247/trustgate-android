package id.fatarc.trustgate.core.keys

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.backend.ReferenceBackend
import id.fatarc.trustgate.core.backend.InProcessTrustGateApi
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.RequiredConfirmation
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.testing.SoftwareKeyProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import org.junit.Test
import java.security.KeyStoreException

class KeyRegistrarTest {
    private val keys = SoftwareKeyProvider()
    private val backend = ReferenceBackend()
    private val registrar = KeyRegistrar(keys, InProcessTrustGateApi(backend), Dispatchers.Unconfined)

    private fun mediumRiskConfirmation(deviceKeyId: String): RequiredConfirmation =
        (backend.beginPayment(deviceKeyId, DeviceRiskLevel.MEDIUM) as PaymentAuthorization.Proceed).confirmation

    @Test
    fun `both keys are registered when a screen lock is set`() = runTest {
        val result = registrar.ensure()

        assertThat(result.newlyRegistered.map { it.role }).containsExactly(KeyRole.DEVICE, KeyRole.STEP_UP).inOrder()
        assertThat(mediumRiskConfirmation(result.keys.device.keyId)).isEqualTo(RequiredConfirmation.STEP_UP_KEY)
    }

    @Test
    fun `a step-up key the system deleted is replaced`() = runTest {
        val first = registrar.ensure().keys
        keys.delete(KeyRole.STEP_UP)

        val second = registrar.ensure()

        assertThat(second.keys.device).isEqualTo(first.device)
        assertThat(second.newlyRegistered.map { it.role }).containsExactly(KeyRole.STEP_UP)
        assertThat(second.keys.stepUp?.keyId).isNotEqualTo(first.stepUp?.keyId)
    }

    @Test
    fun `removing the screen lock drops the step-up key at the backend`() = runTest {
        val device = registrar.ensure().keys.device
        keys.screenLockSet = false

        val keySet = registrar.ensure().keys

        assertThat(keySet.stepUp).isNull()
        assertThat(keySet.stepUpUnavailableReason).isNotNull()
        assertThat(mediumRiskConfirmation(device.keyId)).isEqualTo(RequiredConfirmation.TAP)
    }

    @Test
    fun `a Keystore error is reported instead of replacing the keys`() = runTest {
        val first = registrar.ensure().keys
        keys.keystoreError = KeyStoreException("Keystore is busy")

        val failure = runCatching { registrar.ensure() }.exceptionOrNull()
        keys.keystoreError = null
        val recovered = registrar.ensure()

        assertThat(failure).isInstanceOf(KeyStoreException::class.java)
        assertThat(recovered.keys).isEqualTo(first)
        assertThat(recovered.newlyRegistered).isEmpty()
    }
}

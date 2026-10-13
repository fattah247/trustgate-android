package id.fatarc.trustgate.core.keys

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.core.backend.PaymentAuthorization
import id.fatarc.trustgate.core.backend.ReferenceBackend
import id.fatarc.trustgate.core.backend.RequiredConfirmation
import id.fatarc.trustgate.core.backend.RiskEvidence
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.testing.SoftwareKeyProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import org.junit.Test

class KeyRegistrarTest {
    private val keys = SoftwareKeyProvider()
    private val backend = ReferenceBackend()
    private val registrar = KeyRegistrar(keys, backend, Dispatchers.Unconfined)

    private fun mediumRiskConfirmation(deviceKeyId: String): RequiredConfirmation =
        (backend.beginPayment(deviceKeyId, RiskEvidence(DeviceRiskLevel.MEDIUM, emptySet(), simulated = true)) as PaymentAuthorization.Proceed)
            .confirmation

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
}

package id.fatarc.trustgate.core.keys

import id.fatarc.trustgate.core.backend.TrustGateApi
import id.fatarc.trustgate.domain.api.RegistrationResult
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** The device's keys as the backend knows them. */
data class KeySet(
    val device: RegisteredKey,
    val stepUp: RegisteredKey?,
    /** Why there's no step-up key, when there isn't one. */
    val stepUpUnavailableReason: String?,
)

class KeyRegistrationException(message: String) : Exception(message)

/**
 * Keeps the backend's view of this device's keys current. The device key is registered once per
 * backend lifetime; the step-up key comes and goes with the screen lock.
 */
class KeyRegistrar(
    private val provider: DeviceKeyProvider,
    private val api: TrustGateApi,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    private val lock = Mutex()
    private var current: KeySet? = null

    /** The keys registered so far, and those newly registered by this call so they can be logged. */
    data class Result(val keys: KeySet, val newlyRegistered: List<RegisteredKey>)

    suspend fun ensure(): Result = lock.withLock {
        withContext(ioDispatcher) {
            val added = mutableListOf<RegisteredKey>()
            // Keystore can lose keys behind the app's back, so trust what's registered only while the key exists.
            if (current != null && !provider.hasKey(KeyRole.DEVICE)) current = null
            val device = current?.device ?: register(KeyRole.DEVICE, deviceKeyId = null).also(added::add)
            var stepUp = current?.stepUp
            if (stepUp != null && !provider.hasKey(KeyRole.STEP_UP)) {
                dropStepUp(device.keyId)
                stepUp = null
            }
            var unavailableReason: String? = null

            when (val support = provider.stepUpSupport()) {
                StepUpSupport.Available -> if (stepUp == null) {
                    runCatching { register(KeyRole.STEP_UP, deviceKeyId = device.keyId) }
                        .onSuccess { stepUp = it.also(added::add) }
                        .onFailure { unavailableReason = "The step-up key couldn't be set up: ${it.message}" }
                }

                is StepUpSupport.Unavailable -> {
                    if (stepUp != null) dropStepUp(device.keyId)
                    stepUp = null
                    unavailableReason = support.reason
                }
            }

            val keys = KeySet(device, stepUp, unavailableReason)
            current = keys
            Result(keys, added)
        }
    }

    /** Forgets a step-up key that Keystore reported invalid; the next [ensure] makes a new one. */
    suspend fun invalidateStepUp() = lock.withLock {
        val keys = current ?: return@withLock
        withContext(ioDispatcher) { dropStepUp(keys.device.keyId) }
        current = keys.copy(stepUp = null)
    }

    /** Tells the backend to stop accepting the step-up key, with the device key vouching for the request. */
    private suspend fun dropStepUp(deviceKeyId: String) {
        val challenge = api.registrationChallenge(deviceKeyId)
        val proof = provider.signWithDeviceKey(
            ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_REMOVE_STEP_UP, challenge, deviceKeyId),
        )
        api.removeStepUpKey(deviceKeyId, challenge, proof)
        provider.delete(KeyRole.STEP_UP)
    }

    private suspend fun register(role: KeyRole, deviceKeyId: String?): RegisteredKey {
        val challenge = api.registrationChallenge(deviceKeyId)
        val generated = provider.generate(role, challenge)
        // The device key vouches for a new step-up key, so a key from elsewhere can't be slipped in.
        val proof = deviceKeyId?.let {
            val stepUpKeyId = ReferenceSigningScheme.keyIdFor(generated.encodedPublicKey)
            provider.signWithDeviceKey(
                ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_ADD_STEP_UP, challenge, stepUpKeyId),
            )
        }
        return when (
            val result = api.registerKey(
                role = role,
                encodedPublicKey = generated.encodedPublicKey,
                attestationChain = generated.attestationChain,
                challenge = challenge,
                deviceKeyId = deviceKeyId,
                deviceKeyProof = proof,
            )
        ) {
            is RegistrationResult.Registered -> RegisteredKey(role, result.keyId, generated.protection, result.attestation)
            is RegistrationResult.Refused -> {
                provider.delete(role)
                throw KeyRegistrationException(result.reason)
            }
        }
    }
}

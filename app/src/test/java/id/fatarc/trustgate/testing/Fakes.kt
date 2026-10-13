package id.fatarc.trustgate.testing

import id.fatarc.trustgate.core.attestation.SecurityLevel
import id.fatarc.trustgate.core.keys.DeviceKeyProvider
import id.fatarc.trustgate.core.keys.GeneratedKey
import id.fatarc.trustgate.core.keys.StepUpKeyInvalidatedException
import id.fatarc.trustgate.core.keys.StepUpSupport
import id.fatarc.trustgate.core.storage.SecureValueStore
import id.fatarc.trustgate.core.storage.SecurityStorageSnapshot
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.domain.events.SecurityEventRepository
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.DeviceSignalCollector
import id.fatarc.trustgate.domain.risk.RiskSignal
import id.fatarc.trustgate.domain.signing.KeyRole
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.security.Signature

class FakeSignalCollector(
    private val signals: List<RiskSignal>,
) : DeviceSignalCollector {
    override fun collectSignals(): List<RiskSignal> = signals
}

class MutableSignalCollector(
    var signals: List<RiskSignal>,
) : DeviceSignalCollector {
    override fun collectSignals(): List<RiskSignal> = signals
}

class InMemorySecurityEventRepository : SecurityEventRepository {
    private val state = MutableStateFlow<List<SecurityEvent>>(emptyList())
    override val events: StateFlow<List<SecurityEvent>> = state

    override suspend fun record(event: SecurityEvent) {
        state.value = state.value + event
    }

    override suspend fun clear() {
        state.value = emptyList()
    }
}

class InMemorySecureValueStore : SecureValueStore {
    private var snapshot = SecurityStorageSnapshot()

    override fun readSnapshot(): SecurityStorageSnapshot = snapshot

    override fun storeSessionToken(token: String) {
        snapshot = snapshot.copy(sessionToken = token)
    }

    override fun storeLastRiskLevel(level: DeviceRiskLevel) {
        snapshot = snapshot.copy(lastRiskLevel = level)
    }

    override fun storeShowSignalsOnHome(enabled: Boolean) {
        snapshot = snapshot.copy(showSignalsOnHome = enabled)
    }
}

/** Software keys in place of Keystore. [screenLockSet] decides whether a step-up key can exist. */
class SoftwareKeyProvider(
    var screenLockSet: Boolean = true,
) : DeviceKeyProvider {
    private val keys = HashMap<KeyRole, TestKey>()

    /** How many times the step-up key was asked to sign, which needs the person to authenticate. */
    var stepUpSignaturesHandedOut = 0
        private set

    override fun stepUpSupport(): StepUpSupport =
        if (screenLockSet) StepUpSupport.Available else StepUpSupport.Unavailable("Set a screen lock.")

    override fun generate(role: KeyRole, attestationChallenge: ByteArray): GeneratedKey {
        val key = TestKey().also { keys[role] = it }
        if (role == KeyRole.STEP_UP) stepUpInvalidated = false
        return GeneratedKey(role, key.encodedPublicKey, emptyList(), SecurityLevel.SOFTWARE)
    }

    override fun delete(role: KeyRole) {
        keys.remove(role)
    }

    override fun hasKey(role: KeyRole): Boolean = role in keys

    override fun signWithDeviceKey(data: ByteArray): ByteArray = keys.getValue(KeyRole.DEVICE).sign(data)

    /** Makes the next step-up request fail the way Keystore does after the lock or fingerprints change. */
    var stepUpInvalidated = false

    override fun stepUpSignature(): Signature {
        if (stepUpInvalidated) {
            keys.remove(KeyRole.STEP_UP)
            throw StepUpKeyInvalidatedException(IllegalStateException("Key permanently invalidated"))
        }
        stepUpSignaturesHandedOut++
        return keys.getValue(KeyRole.STEP_UP).signature()
    }
}

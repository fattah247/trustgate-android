package id.fatarc.trustgate

import android.content.Context
import id.fatarc.trustgate.core.backend.PaymentClient
import id.fatarc.trustgate.core.backend.ReferenceBackend
import id.fatarc.trustgate.core.backend.ReferenceTransport
import id.fatarc.trustgate.core.crypto.PinnedHttpClientFactory
import id.fatarc.trustgate.core.crypto.PinningConfig
import id.fatarc.trustgate.core.keys.AndroidDeviceKeyProvider
import id.fatarc.trustgate.core.keys.DeviceKeyProvider
import id.fatarc.trustgate.core.keys.KeyRegistrar
import id.fatarc.trustgate.core.security.AndroidDeviceSignalCollector
import id.fatarc.trustgate.core.security.TrustGateSecurityService
import id.fatarc.trustgate.core.storage.KeystoreSecureValueStore
import id.fatarc.trustgate.core.storage.SecureValueStore
import id.fatarc.trustgate.data.securityevent.PersistedSecurityEventRepository
import id.fatarc.trustgate.domain.events.SecurityEventRepository
import id.fatarc.trustgate.domain.risk.RiskScorer
import id.fatarc.trustgate.domain.signing.ReferenceRequestSigner
import id.fatarc.trustgate.domain.signing.RequestSigner

class TrustGateAppContainer(
    context: Context,
) {
    val securityEventRepository: SecurityEventRepository = PersistedSecurityEventRepository(context)
    val secureValueStore: SecureValueStore = KeystoreSecureValueStore(context)
    val requestSigner: RequestSigner = ReferenceRequestSigner()

    // One backend for the app's lifetime, so registered keys and spent challenges persist across screens.
    val backend = ReferenceBackend()
    val keyProvider: DeviceKeyProvider = AndroidDeviceKeyProvider(context)
    val keyRegistrar = KeyRegistrar(keyProvider, backend)
    val transport = ReferenceTransport(backend)
    val paymentClient = PaymentClient(transport)

    val pinningConfig = PinningConfig()
    val pinnedHttpClientFactory = PinnedHttpClientFactory()
    val securityService = TrustGateSecurityService(
        signalCollector = AndroidDeviceSignalCollector(context),
        riskScorer = RiskScorer(),
        eventRepository = securityEventRepository,
    )
}

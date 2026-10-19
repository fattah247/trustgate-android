package id.fatarc.trustgate

import android.content.Context
import id.fatarc.trustgate.backend.ReferenceBackend
import id.fatarc.trustgate.backend.attestation.AttestationPolicy
import id.fatarc.trustgate.core.backend.BackendTransport
import id.fatarc.trustgate.core.backend.InProcessTrustGateApi
import id.fatarc.trustgate.core.backend.PaymentClient
import id.fatarc.trustgate.core.backend.TrustGateApi
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

class TrustGateAppContainer(
    context: Context,
) {
    val securityEventRepository: SecurityEventRepository = PersistedSecurityEventRepository(context)
    val secureValueStore: SecureValueStore = KeystoreSecureValueStore(context)
    val requestSigner = ReferenceRequestSigner()

    // One backend for the app's lifetime, so registered keys and spent challenges persist across screens.
    val api: TrustGateApi = InProcessTrustGateApi(
        ReferenceBackend(AttestationPolicy.development(BuildConfig.APPLICATION_ID, signingCertificateDigests = emptySet())),
    )
    val keyProvider: DeviceKeyProvider = AndroidDeviceKeyProvider(context)
    val keyRegistrar = KeyRegistrar(keyProvider, api)
    val transport = BackendTransport(api)
    val paymentClient = PaymentClient(transport)

    val pinningConfig = PinningConfig()
    val pinnedHttpClientFactory = PinnedHttpClientFactory()
    val securityService = TrustGateSecurityService(
        signalCollector = AndroidDeviceSignalCollector(context),
        riskScorer = RiskScorer(),
        eventRepository = securityEventRepository,
    )
}

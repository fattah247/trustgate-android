package id.fatarc.trustgate

import android.content.Context
import id.fatarc.trustgate.core.crypto.HmacRequestSigner
import id.fatarc.trustgate.core.crypto.PinnedHttpClientFactory
import id.fatarc.trustgate.core.crypto.PinningConfig
import id.fatarc.trustgate.core.security.AndroidDeviceSignalCollector
import id.fatarc.trustgate.core.security.TrustGateSecurityService
import id.fatarc.trustgate.core.storage.EncryptedSecurityStore
import id.fatarc.trustgate.core.storage.SecureValueStore
import id.fatarc.trustgate.data.securityevent.PersistedSecurityEventRepository
import id.fatarc.trustgate.domain.actiongate.SensitiveActionGate
import id.fatarc.trustgate.domain.events.SecurityEventRepository
import id.fatarc.trustgate.domain.risk.RiskScorer
import id.fatarc.trustgate.domain.signing.RequestSigner

class TrustGateAppContainer(
    context: Context,
) {
    val securityEventRepository: SecurityEventRepository = PersistedSecurityEventRepository(context)
    val secureValueStore: SecureValueStore = EncryptedSecurityStore(context)
    val requestSigner: RequestSigner = HmacRequestSigner()
    val pinningConfig = PinningConfig()
    val pinnedHttpClientFactory = PinnedHttpClientFactory()
    val securityService = TrustGateSecurityService(
        signalCollector = AndroidDeviceSignalCollector(context),
        riskScorer = RiskScorer(),
        actionGate = SensitiveActionGate(),
        eventRepository = securityEventRepository,
    )
}


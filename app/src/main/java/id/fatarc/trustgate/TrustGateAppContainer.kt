package id.fatarc.trustgate

import android.content.Context
import android.os.Build
import id.fatarc.trustgate.core.backend.BackendTransport
import id.fatarc.trustgate.core.backend.HttpTrustGateApi
import id.fatarc.trustgate.core.backend.PaymentClient
import id.fatarc.trustgate.core.backend.TrustGateApi
import id.fatarc.trustgate.core.integrity.IntegrityTokenSource
import id.fatarc.trustgate.core.integrity.MockIntegrityTokenSource
import id.fatarc.trustgate.core.integrity.PlayIntegrityTokenSource
import id.fatarc.trustgate.core.keys.AndroidDeviceKeyProvider
import id.fatarc.trustgate.core.keys.DeviceKeyProvider
import id.fatarc.trustgate.core.keys.KeyRegistrar
import id.fatarc.trustgate.core.keys.PreferencesRegisteredKeyStore
import id.fatarc.trustgate.core.security.AndroidDeviceSignalCollector
import id.fatarc.trustgate.core.security.ScreenRecordingMonitor
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

    val api: TrustGateApi = HttpTrustGateApi(BuildConfig.SERVER_URL)
    val keyProvider: DeviceKeyProvider = AndroidDeviceKeyProvider(context)
    val keyRegistrar = KeyRegistrar(
        provider = keyProvider,
        api = api,
        registered = PreferencesRegisteredKeyStore(context),
        phoneLabel = "${Build.MANUFACTURER.replaceFirstChar { it.uppercase() }} ${Build.MODEL}",
    )
    val transport = BackendTransport(api)
    val paymentClient = PaymentClient(transport)
    val integrityTokens: IntegrityTokenSource = when {
        BuildConfig.PLAY_INTEGRITY_PROJECT_NUMBER > 0 -> PlayIntegrityTokenSource(context, BuildConfig.PLAY_INTEGRITY_PROJECT_NUMBER)
        BuildConfig.DEBUG -> MockIntegrityTokenSource()
        else -> IntegrityTokenSource { null }
    }

    val screenRecording = ScreenRecordingMonitor()

    val securityService = TrustGateSecurityService(
        signalCollector = AndroidDeviceSignalCollector(context, screenRecording),
        riskScorer = RiskScorer(),
        eventRepository = securityEventRepository,
    )
}

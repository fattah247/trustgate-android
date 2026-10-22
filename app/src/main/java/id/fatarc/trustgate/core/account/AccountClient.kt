package id.fatarc.trustgate.core.account

import id.fatarc.trustgate.core.backend.TrustGateApi
import id.fatarc.trustgate.core.keys.DeviceKeyProvider
import id.fatarc.trustgate.domain.api.AccountView
import id.fatarc.trustgate.domain.api.DecisionChallenge
import id.fatarc.trustgate.domain.api.DecisionChallengeRequest
import id.fatarc.trustgate.domain.api.DecisionResult
import id.fatarc.trustgate.domain.api.JoinResult
import id.fatarc.trustgate.domain.api.LinkCode
import id.fatarc.trustgate.domain.api.PhoneDecision
import id.fatarc.trustgate.domain.api.SignedAction
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme

/**
 * This phone's part in its account: seeing the account's phones, letting another phone ask to
 * join, joining one, and deciding about the others. Everything is signed by the device key over a
 * fresh challenge, and the decisions also by the key the server asks for.
 */
class AccountClient(
    private val keys: DeviceKeyProvider,
    private val api: TrustGateApi,
) {
    suspend fun view(deviceKeyId: String): AccountView = api.accountView(signed(ReferenceSigningScheme.ACTION_VIEW_ACCOUNT, deviceKeyId))

    suspend fun createLinkCode(deviceKeyId: String): LinkCode = api.createLinkCode(signed(ReferenceSigningScheme.ACTION_LINK_CODE, deviceKeyId))

    suspend fun join(deviceKeyId: String, code: String): JoinResult =
        api.joinAccount(signed(ReferenceSigningScheme.ACTION_JOIN_ACCOUNT, deviceKeyId, ReferenceSigningScheme.normalizeLinkCode(code)))

    suspend fun decisionChallenge(deviceKeyId: String, phoneId: String, action: String): DecisionChallenge =
        api.decisionChallenge(DecisionChallengeRequest(deviceKeyId, phoneId, action))

    suspend fun decide(decision: PhoneDecision): DecisionResult = api.decide(decision)

    private suspend fun signed(action: String, deviceKeyId: String, subject: String = ""): SignedAction {
        val challenge = api.registrationChallenge(deviceKeyId)
        val proof = keys.signWithDeviceKey(ReferenceSigningScheme.keyBindingInput(action, challenge, subject))
        return SignedAction(deviceKeyId, ReferenceSigningScheme.encode(challenge), ReferenceSigningScheme.encode(proof), subject)
    }
}

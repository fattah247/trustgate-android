package id.fatarc.trustgate.testing

import id.fatarc.trustgate.backend.ReferenceBackend
import id.fatarc.trustgate.domain.api.DecisionChallengeRequest
import id.fatarc.trustgate.domain.api.PhoneDecision
import id.fatarc.trustgate.domain.api.SignedAction
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme

/** [action] about [subject], signed by [key] over a fresh challenge, the way a phone makes account requests. */
fun ReferenceBackend.signedAction(key: TestKey, action: String, subject: String = ""): SignedAction {
    val challenge = issueRegistrationChallenge(key.keyId)
    val proof = key.sign(ReferenceSigningScheme.keyBindingInput(action, challenge, subject))
    return SignedAction(key.keyId, ReferenceSigningScheme.encode(challenge), ReferenceSigningScheme.encode(proof), subject)
}

/** [decider] decides [action] about [phone]'s phone, signing with [signingKey], by tap when [tap]. */
fun ReferenceBackend.decideAbout(
    decider: TestKey,
    phone: TestKey,
    action: String,
    signingKey: TestKey = decider,
    tap: Boolean = true,
): Boolean = decideAbout(decider, phone.keyId, action, signingKey, tap)

/** [decider] decides [action] about the phone [phoneId], for a phone whose keys a test doesn't hold. */
fun ReferenceBackend.decideAbout(
    decider: TestKey,
    phoneId: String,
    action: String,
    signingKey: TestKey = decider,
    tap: Boolean = true,
): Boolean {
    val challenge = decisionChallenge(DecisionChallengeRequest(decider.keyId, phoneId, action)) ?: return false
    val signature = signingKey.sign(ReferenceSigningScheme.decisionInput(action, challenge.nonce, phoneId, tap))
    return decide(PhoneDecision(signingKey.keyId, phoneId, action, challenge.nonce, ReferenceSigningScheme.encode(signature), tap)).done
}

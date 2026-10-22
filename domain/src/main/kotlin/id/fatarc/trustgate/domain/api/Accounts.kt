package id.fatarc.trustgate.domain.api

import id.fatarc.trustgate.domain.signing.KeyRole
import kotlinx.serialization.Serializable

/**
 * Something a phone asks of its account, signed by its device key: [proof] is the device key's
 * signature over the action, a registration challenge the server issued to this phone, and [subject].
 */
@Serializable
data class SignedAction(
    val deviceKeyId: String,
    val challenge: String,
    val proof: String,
    /** What the action is about: a link code, another phone's ID, or empty. */
    val subject: String = "",
)

/** The phones on an account, as one of them sees it. */
@Serializable
data class AccountView(
    val accountId: String,
    val phones: List<PhoneView>,
    /** This phone asked to join another account, and waits for a phone there to approve it. */
    val waitingToJoin: Boolean = false,
)

@Serializable
enum class PhoneStatus {
    /** On the account and trusted like any other phone. */
    ACTIVE,

    /** On the account recently, so the new-phone rules still apply to it. */
    NEW,

    /** Asked to join with a link code and waits for a phone on the account to approve it. */
    WAITING_FOR_APPROVAL,
}

@Serializable
data class PhoneView(
    val phoneId: String,
    /** The phone's model, as it said when it registered. */
    val label: String,
    /** ISO-8601 instant the phone joined this account. */
    val joinedAt: String,
    val status: PhoneStatus,
    val thisPhone: Boolean,
)

/** A one-time code another phone enters to ask to join this account. */
@Serializable
data class LinkCode(val code: String, val expiresAt: String)

@Serializable
data class JoinResult(val waitingForApproval: Boolean, val message: String)

/** The phone deciding about another one asks for a challenge, and learns which key must sign. */
@Serializable
data class DecisionChallengeRequest(val deviceKeyId: String, val phoneId: String, val action: String)

@Serializable
data class DecisionChallenge(val nonce: String, val signWith: KeyRole, val confirmation: RequiredConfirmation)

/** Approves, declines, or removes [phoneId], signed by the key the challenge asked for. */
@Serializable
data class PhoneDecision(
    val keyId: String,
    val phoneId: String,
    val action: String,
    val nonce: String,
    val signature: String,
    /** Set when the deciding phone has no screen lock and the person confirmed with a tap. */
    val tapConfirmed: Boolean = false,
)

@Serializable
data class DecisionResult(val done: Boolean, val message: String)

package id.fatarc.trustgate.backend

import id.fatarc.trustgate.backend.attestation.KeyAttestationVerifier
import id.fatarc.trustgate.backend.attestation.RevocationList
import id.fatarc.trustgate.backend.attestation.toSummary
import id.fatarc.trustgate.backend.audit.AuditLog
import id.fatarc.trustgate.backend.store.BackendStore
import id.fatarc.trustgate.backend.store.ChallengePurpose
import id.fatarc.trustgate.backend.store.InMemoryBackendStore
import id.fatarc.trustgate.backend.store.LedgerEntry
import id.fatarc.trustgate.backend.store.StoredChallenge
import id.fatarc.trustgate.backend.store.StoredKey
import id.fatarc.trustgate.backend.store.StoredLinkCode
import id.fatarc.trustgate.backend.store.StoredPhone
import id.fatarc.trustgate.domain.actiongate.SensitiveActionDecision
import id.fatarc.trustgate.domain.actiongate.SensitiveActionGate
import id.fatarc.trustgate.domain.api.AccountView
import id.fatarc.trustgate.domain.api.AuditStatus
import id.fatarc.trustgate.domain.api.DecisionChallenge
import id.fatarc.trustgate.domain.api.DecisionChallengeRequest
import id.fatarc.trustgate.domain.api.DecisionReason
import id.fatarc.trustgate.domain.api.DecisionResult
import id.fatarc.trustgate.domain.api.DeviceEvidence
import id.fatarc.trustgate.domain.api.JoinResult
import id.fatarc.trustgate.domain.api.LinkCode
import id.fatarc.trustgate.domain.api.Payment
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.PaymentResponse
import id.fatarc.trustgate.domain.api.PhoneDecision
import id.fatarc.trustgate.domain.api.PhoneStatus
import id.fatarc.trustgate.domain.api.PhoneView
import id.fatarc.trustgate.domain.api.RegistrationResult
import id.fatarc.trustgate.domain.api.RequiredConfirmation
import id.fatarc.trustgate.domain.api.SignedAction
import id.fatarc.trustgate.domain.api.TrustGateJson
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.PaymentRequestPayload
import id.fatarc.trustgate.domain.signing.ReceivedRequest
import id.fatarc.trustgate.domain.signing.ReferenceRequestSigner
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.domain.signing.RejectionReason
import id.fatarc.trustgate.domain.signing.VerificationResult
import java.security.KeyFactory
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.format.DateTimeParseException
import kotlinx.serialization.json.Json

/**
 * The server's part: it registers device keys from their attestation, issues one-time challenges,
 * makes the gate decision, and processes payments idempotently. Each call runs in one [store]
 * transaction, so a crash can't leave a challenge spent without the payment it paid for.
 */
class ReferenceBackend(
    private val policy: BackendPolicy,
    private val clock: Clock = Clock.systemUTC(),
    /** The latest copy of Google's status list; the server refreshes it in the background. */
    private val revocations: () -> RevocationList? = { RevocationList.EMPTY },
    private val store: BackendStore = InMemoryBackendStore(),
) {
    private val gate = SensitiveActionGate()
    private val random = SecureRandom()
    private val audit = AuditLog(store, clock)
    private val canonical = ReferenceRequestSigner()

    /** How many payments were actually charged, however many requests arrived. */
    val chargedPayments: Int @Synchronized get() = store.transaction { store.ledgerSize() }

    /** Checks the audit log's hash chain from its first entry. */
    @Synchronized
    fun auditStatus(): AuditStatus = store.transaction { audit.verify() }

    /**
     * A one-time registration challenge. Pass [deviceKeyId] to add or remove that device's step-up
     * key; those operations also need a signature from the device key.
     */
    @Synchronized
    fun issueRegistrationChallenge(deviceKeyId: String? = null): ByteArray = store.transaction {
        val bytes = ByteArray(32).also(random::nextBytes)
        store.putChallenge(
            StoredChallenge(
                nonce = ReferenceSigningScheme.encode(bytes),
                purpose = ChallengePurpose.REGISTRATION,
                deviceKeyId = deviceKeyId,
                confirmation = RequiredConfirmation.NONE,
                expiresAt = clock.instant().plus(CHALLENGE_LIFETIME),
            ),
        )
        bytes
    }

    /**
     * Registers a key from its certificate chain, as [policy] allows. A step-up key must be vouched
     * for by its device: [deviceKeyProof] is the device key's signature over
     * [ReferenceSigningScheme.keyBindingInput] for this challenge and key.
     */
    @Synchronized
    fun registerKey(
        role: KeyRole,
        encodedPublicKey: ByteArray,
        attestationChain: List<ByteArray>,
        challenge: ByteArray,
        deviceKeyId: String? = null,
        deviceKeyProof: ByteArray? = null,
        phoneLabel: String? = null,
    ): RegistrationResult = store.transaction {
        val result = register(role, encodedPublicKey, attestationChain, challenge, deviceKeyId, deviceKeyProof, phoneLabel)
        when (result) {
            is RegistrationResult.Registered -> audit.record(
                "key-registered",
                subject = store.key(result.keyId)?.phoneId ?: result.keyId,
                detail = "${role.name.lowercase()} key ${result.keyId}, attested=${result.attestation.attested}",
            )
            is RegistrationResult.Refused -> audit.record(
                "registration-refused",
                subject = deviceKeyId ?: ReferenceSigningScheme.keyIdFor(encodedPublicKey),
                detail = result.reason,
            )
        }
        result
    }

    private fun register(
        role: KeyRole,
        encodedPublicKey: ByteArray,
        attestationChain: List<ByteArray>,
        challenge: ByteArray,
        deviceKeyId: String?,
        deviceKeyProof: ByteArray?,
        phoneLabel: String?,
    ): RegistrationResult {
        if (!spendRegistrationChallenge(challenge, deviceKeyId)) {
            return RegistrationResult.Refused("The registration challenge doesn't match this request, or has expired.")
        }
        decodePublicKey(encodedPublicKey) ?: return RegistrationResult.Refused("The public key couldn't be read.")
        val keyId = ReferenceSigningScheme.keyIdFor(encodedPublicKey)
        if (store.key(keyId) != null) return RegistrationResult.Refused("This key is already registered.")

        val attestation = KeyAttestationVerifier.verify(attestationChain, encodedPublicKey, challenge)
        policy.attestation.problemWith(attestation, revocations())?.let { return RegistrationResult.Refused(it) }

        fun stored(owner: String, phoneId: String, phoneEnrolledAt: Instant) = StoredKey(
            keyId = keyId,
            role = role,
            encodedPublicKey = encodedPublicKey,
            deviceKeyId = owner,
            attested = attestation.isAttested,
            rootKeyFingerprint = attestation.rootKeyFingerprint,
            registeredAt = clock.instant(),
            phoneId = phoneId,
            phoneEnrolledAt = phoneEnrolledAt,
        )
        when (role) {
            KeyRole.DEVICE -> {
                if (deviceKeyId != null) return RegistrationResult.Refused("A device key can't belong to another key.")
                store.putKey(stored(owner = keyId, phoneId = keyId, phoneEnrolledAt = clock.instant()))
                // A phone starts on an account of its own; joining another needs a phone there to approve it.
                store.putPhone(StoredPhone(keyId, newId("acc_"), cleanLabel(phoneLabel), clock.instant()))
            }

            KeyRole.STEP_UP -> {
                val owner = deviceKeyId?.let(store::key)?.takeIf { it.role == KeyRole.DEVICE && !it.isRevoked }
                    ?: return RegistrationResult.Refused("A step-up key needs a registered device key.")
                val vouched = deviceKeyProof != null && verifySignature(
                    owner,
                    ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_ADD_STEP_UP, challenge, keyId),
                    deviceKeyProof,
                )
                if (!vouched) return RegistrationResult.Refused("The device key didn't vouch for this step-up key.")
                if (owner.attested) {
                    if (!attestation.isAttested) return RegistrationResult.Refused("An attested device needs an attested step-up key.")
                    if (attestation.rootKeyFingerprint != owner.rootKeyFingerprint) {
                        return RegistrationResult.Refused("The step-up key was attested by a different root than the device key.")
                    }
                }
                // A step-up key whose attestation says it signs without authentication isn't a step-up key.
                val description = attestation.description
                if (description != null && !description.userAuthRequired) {
                    return RegistrationResult.Refused("The attestation shows this key doesn't require authentication.")
                }
                if ((description?.authTimeoutSeconds ?: 0) > 0) {
                    return RegistrationResult.Refused("The key stays unlocked for a while after one authentication instead of asking for each signature.")
                }
                store.stepUpKeyOf(owner.keyId)?.let(store::deleteKey)
                store.putKey(stored(owner = owner.keyId, phoneId = owner.phoneId, phoneEnrolledAt = owner.phoneEnrolledAt))
                store.setStepUpKey(owner.keyId, keyId)
            }
        }
        return RegistrationResult.Registered(keyId, role, attestation.toSummary(trustedRoot = policy.attestation.trustsRoot(attestation)))
    }

    /**
     * Drops a device's step-up key when its screen lock is gone, so medium risk falls back to a tap.
     * The device key must sign the request, or anyone who knew its key ID could downgrade it.
     */
    @Synchronized
    fun removeStepUpKey(deviceKeyId: String, challenge: ByteArray, deviceKeyProof: ByteArray): Boolean = store.transaction {
        if (!spendRegistrationChallenge(challenge, deviceKeyId)) return@transaction false
        val owner = store.key(deviceKeyId)?.takeIf { it.role == KeyRole.DEVICE && !it.isRevoked } ?: return@transaction false
        val vouched = verifySignature(
            owner,
            ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_REMOVE_STEP_UP, challenge, deviceKeyId),
            deviceKeyProof,
        )
        if (!vouched) return@transaction false
        store.stepUpKeyOf(deviceKeyId)?.let(store::deleteKey)
        store.setStepUpKey(deviceKeyId, null)
        audit.record("step-up-removed", subject = owner.phoneId, detail = "device key $deviceKeyId")
        true
    }

    /**
     * Replaces a phone's device key with a new one. The current key vouches for its successor by
     * signing the rotate action over [challenge] and the new key's ID; the new key must pass the same
     * attestation checks as any registration. The phone keeps its identity, history, and limits, and
     * the old key and its step-up key are never accepted again.
     */
    @Synchronized
    fun rotateDeviceKey(
        currentKeyId: String,
        encodedPublicKey: ByteArray,
        attestationChain: List<ByteArray>,
        challenge: ByteArray,
        proof: ByteArray,
    ): RegistrationResult = store.transaction {
        fun refuse(reason: String): RegistrationResult {
            audit.record("rotation-refused", subject = currentKeyId, detail = reason)
            return RegistrationResult.Refused(reason)
        }
        val current = store.key(currentKeyId)?.takeIf { it.role == KeyRole.DEVICE && !it.isRevoked }
            ?: return@transaction refuse("This phone's key isn't registered.")
        if (!spendRegistrationChallenge(challenge, currentKeyId)) return@transaction refuse("The challenge doesn't match, or has expired.")
        decodePublicKey(encodedPublicKey) ?: return@transaction refuse("The public key couldn't be read.")
        val keyId = ReferenceSigningScheme.keyIdFor(encodedPublicKey)
        if (store.key(keyId) != null) return@transaction refuse("This key is already registered.")
        val vouched = verifySignature(current, ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_ROTATE_DEVICE, challenge, keyId), proof)
        if (!vouched) return@transaction refuse("The current key didn't vouch for the new one.")

        val attestation = KeyAttestationVerifier.verify(attestationChain, encodedPublicKey, challenge)
        policy.attestation.problemWith(attestation, revocations())?.let { return@transaction refuse(it) }
        // A phone that proved its hardware once can't continue on a key that proves less.
        if (current.attested && (!attestation.isAttested || attestation.rootKeyFingerprint != current.rootKeyFingerprint)) {
            return@transaction refuse("The new key isn't attested the way the current one was.")
        }

        val now = clock.instant()
        store.putKey(
            StoredKey(
                keyId = keyId,
                role = KeyRole.DEVICE,
                encodedPublicKey = encodedPublicKey,
                deviceKeyId = keyId,
                attested = attestation.isAttested,
                rootKeyFingerprint = attestation.rootKeyFingerprint,
                registeredAt = now,
                phoneId = current.phoneId,
                phoneEnrolledAt = current.phoneEnrolledAt,
            ),
        )
        revokePhoneKeys(current, now, "Replaced by $keyId")
        audit.record("key-rotated", subject = current.phoneId, detail = "$currentKeyId replaced by $keyId")
        RegistrationResult.Registered(keyId, KeyRole.DEVICE, attestation.toSummary(trustedRoot = policy.attestation.trustsRoot(attestation)))
    }

    /** The phone asks to be forgotten, for example before it's sold. Its device key signs the request. */
    @Synchronized
    fun removeDevice(deviceKeyId: String, challenge: ByteArray, proof: ByteArray): Boolean = store.transaction {
        if (!spendRegistrationChallenge(challenge, deviceKeyId)) return@transaction false
        val device = store.key(deviceKeyId)?.takeIf { it.role == KeyRole.DEVICE && !it.isRevoked } ?: return@transaction false
        val vouched = verifySignature(device, ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_REMOVE_DEVICE, challenge, deviceKeyId), proof)
        if (!vouched) return@transaction false
        revokePhoneKeys(device, clock.instant(), "Removed by the phone")
        audit.record("phone-removed", subject = device.phoneId, detail = "by the phone")
        true
    }

    /** An operator stops accepting a phone, given either of its keys. False when there's nothing live to revoke. */
    @Synchronized
    fun revokeByOperator(keyId: String, reason: String): Boolean = store.transaction {
        val key = store.key(keyId) ?: return@transaction false
        val device = store.key(key.deviceKeyId)?.takeIf { !it.isRevoked } ?: return@transaction false
        revokePhoneKeys(device, clock.instant(), "Revoked by an operator: $reason")
        audit.record("phone-revoked", subject = device.phoneId, detail = reason)
        true
    }

    /** Revokes [device] and its step-up key, which can't outlive the key that vouched for it. */
    private fun revokePhoneKeys(device: StoredKey, at: Instant, reason: String) {
        store.stepUpKeyOf(device.keyId)?.let(store::key)?.let { store.putKey(it.revoked(at, reason)) }
        store.setStepUpKey(device.keyId, null)
        store.putKey(device.revoked(at, reason))
    }

    /** A one-time challenge for signing a request only to have it checked, with nothing charged. */
    @Synchronized
    fun issueVerificationChallenge(deviceKeyId: String): String = store.transaction {
        issueChallenge(ChallengePurpose.VERIFICATION, deviceKeyId, RequiredConfirmation.NONE)
    }

    /**
     * Decides whether a protected action may run, here rather than in the app. [evidence] is the
     * [DeviceEvidence] JSON exactly as the device key signed it, and [integrityToken] a Play Integrity
     * token bound to its hash. The answer carries the challenge the payment must sign and the key
     * it must be signed with.
     */
    @Synchronized
    fun authorizePayment(
        deviceKeyId: String,
        evidence: String,
        signature: ByteArray,
        integrityToken: String?,
        receivedAt: Instant = clock.instant(),
    ): PaymentAuthorization = store.transaction {
        fun refuse(reason: String, keyRejected: Boolean = false): PaymentAuthorization {
            audit.record("authorization-refused", subject = deviceKeyId, detail = reason)
            return PaymentAuthorization.Blocked(DeviceRiskLevel.HIGH, listOf(DecisionReason(reason, DeviceRiskLevel.HIGH)), keyRejected = keyRejected)
        }
        val key = store.key(deviceKeyId)?.takeIf { it.role == KeyRole.DEVICE }
            ?: return@transaction refuse("Unknown phone", keyRejected = true)
        if (key.isRevoked) return@transaction refuse("Phone removed", keyRejected = true)
        if (!verifySignature(key, evidence.toByteArray(), signature)) return@transaction refuse("Report not signed by this phone")
        val report = runCatching { TrustGateJson.decodeFromString(DeviceEvidence.serializer(), evidence) }.getOrNull()
            ?.takeIf { it.deviceKeyId == deviceKeyId }
            ?: return@transaction refuse("Report unreadable")
        val collectedAt = runCatching { Instant.parse(report.collectedAt) }.getOrNull()
        if (collectedAt == null || Duration.between(collectedAt, receivedAt).abs() > ReferenceSigningScheme.TIME_WINDOW) {
            return@transaction refuse("Report out of date")
        }
        // The challenge is bound to these details, so they must be there to bind to.
        val payment = report.payment?.takeIf { it.amountMinor > 0 && it.currency.isNotBlank() && it.payee.isNotBlank() }
            ?: return@transaction refuse("Payment details missing")
        val assessment = policy.risk.assess(report, ReferenceSigningScheme.sha256Hex(evidence), integrityToken, receivedAt)
        val authorization = authorization(key, payment, assessment + history(key, payment, receivedAt), receivedAt)
        audit.record(
            "payment-authorized",
            subject = key.phoneId,
            detail = "${authorization.decision.name.lowercase()} at ${authorization.level.name.lowercase()}: " +
                authorization.reasons.joinToString("; ") { it.text },
        )
        authorization
    }

    /**
     * What the phone's record adds to its report. Charging enforces the limits whatever this says;
     * saying it here first spares the person a confirmation that would end in a refusal.
     */
    private fun history(deviceKey: StoredKey, payment: PaymentRequestPayload, at: Instant): List<DecisionReason> = buildList {
        when (limitBroken(deviceKey, payment.amountMinor, at)) {
            RejectionReason.TOO_MANY_PAYMENTS -> add(DecisionReason("Too many payments. Try again in a few minutes", DeviceRiskLevel.HIGH))
            RejectionReason.OVER_LIMIT -> add(DecisionReason("Over this phone's limit", DeviceRiskLevel.HIGH))
            else -> Unit
        }
        if (isNewPhone(deviceKey, at)) add(DecisionReason("New phone", DeviceRiskLevel.MEDIUM))
    }

    private fun isNewPhone(deviceKey: StoredKey, at: Instant): Boolean = isNewPhone(phoneOf(deviceKey), at)

    /** New since it enrolled or joined its account, whichever came later. */
    private fun isNewPhone(phone: StoredPhone, at: Instant): Boolean =
        policy.limits.newPhonePeriod?.let { period -> phone.joinedAt.isAfter(at.minus(period)) } == true

    /** The phone [deviceKey] belongs to; one registered before accounts existed gets an account of its own. */
    private fun phoneOf(deviceKey: StoredKey): StoredPhone = store.phone(deviceKey.phoneId)
        ?: StoredPhone(deviceKey.phoneId, newId("acc_"), "Phone", deviceKey.phoneEnrolledAt).also(store::putPhone)

    /** Why charging [amountMinor] now would break the phone's limits, or null when it wouldn't. */
    private fun limitBroken(deviceKey: StoredKey, amountMinor: Long, at: Instant): RejectionReason? {
        val limits = policy.limits
        // Counted across every phone on the account, so adding a phone doesn't add allowance.
        val account = phoneOf(deviceKey).accountId
        if (store.paymentsOfAccount(account, at.minus(limits.window)).size >= limits.maxPayments) {
            return RejectionReason.TOO_MANY_PAYMENTS
        }
        val daily = limits.dailyAmountMinor
        if (daily != null && store.paymentsOfAccount(account, at.minus(Duration.ofDays(1))).sumOf { it.amountMinor } + amountMinor > daily) {
            return RejectionReason.OVER_LIMIT
        }
        val newPhoneCap = limits.newPhoneAmountMinor
        if (newPhoneCap != null && isNewPhone(deviceKey, at) && amountMinor > newPhoneCap) {
            return RejectionReason.OVER_LIMIT
        }
        return null
    }

    private fun authorization(
        deviceKey: StoredKey,
        payment: PaymentRequestPayload,
        assessment: RiskPolicy.Assessment,
        at: Instant,
    ): PaymentAuthorization {
        val deviceKeyId = deviceKey.keyId
        val level = assessment.level
        return when (val decision = gate.decide(level)) {
            SensitiveActionDecision.BLOCK ->
                PaymentAuthorization.Blocked(level, assessment.reasons, assessment.remedy, assessment.scamWarning)
            SensitiveActionDecision.ALLOW,
            SensitiveActionDecision.REQUIRE_CONFIRMATION,
            -> {
                val stepUp = decision == SensitiveActionDecision.REQUIRE_CONFIRMATION
                val hasStepUpKey = store.stepUpKeyOf(deviceKeyId) != null
                val signWith = if (stepUp && hasStepUpKey) KeyRole.STEP_UP else KeyRole.DEVICE
                val confirmation = when {
                    !stepUp -> RequiredConfirmation.NONE
                    hasStepUpKey -> RequiredConfirmation.STEP_UP_KEY
                    else -> RequiredConfirmation.TAP
                }
                val boundHash = ReferenceSigningScheme.sha256Hex(canonical.canonicalize(payment))
                val nonce = issueChallenge(ChallengePurpose.PAYMENT, deviceKeyId, confirmation, boundHash)
                PaymentAuthorization.Proceed(
                    decision = decision,
                    level = level,
                    nonce = nonce,
                    signWith = signWith,
                    confirmation = confirmation,
                    reasons = assessment.reasons,
                    remedy = assessment.remedy,
                    scamWarning = assessment.scamWarning,
                    rotateKey = policy.keyMaxAge?.let { deviceKey.registeredAt.isBefore(at.minus(it)) } == true,
                )
            }
        }
    }

    // Accounts: the phones that act for one person, and how a new one gets added.

    /** The account [action]'s phone belongs to, with its phones and those waiting to join. */
    @Synchronized
    fun accountView(action: SignedAction): AccountView? = store.transaction {
        val device = signedBy(action, ReferenceSigningScheme.ACTION_VIEW_ACCOUNT) ?: return@transaction null
        val phone = phoneOf(device)
        val now = clock.instant()
        AccountView(
            accountId = phone.accountId,
            phones = store.phonesOf(phone.accountId)
                .filter { store.activeDeviceKey(it.phoneId) != null }
                .map { other ->
                    PhoneView(
                        phoneId = other.phoneId,
                        label = other.label,
                        joinedAt = other.joinedAt.toString(),
                        status = when {
                            other.accountId != phone.accountId -> PhoneStatus.WAITING_FOR_APPROVAL
                            isNewPhone(other, now) -> PhoneStatus.NEW
                            else -> PhoneStatus.ACTIVE
                        },
                        thisPhone = other.phoneId == phone.phoneId,
                    )
                },
            waitingToJoin = phone.pendingAccountId != null,
        )
    }

    /**
     * A one-time code another phone enters to ask to join this account. Only a phone that's been on
     * the account past the new-phone period can make one, so a phone that just got in can't let more in.
     */
    @Synchronized
    fun createLinkCode(action: SignedAction): LinkCode? = store.transaction {
        val device = signedBy(action, ReferenceSigningScheme.ACTION_LINK_CODE) ?: return@transaction null
        val phone = phoneOf(device)
        if (isNewPhone(phone, clock.instant())) return@transaction null
        val code = StoredLinkCode(newLinkCode(), phone.accountId, phone.phoneId, clock.instant().plus(LINK_CODE_LIFETIME))
        store.putLinkCode(code)
        audit.record("link-code-issued", subject = phone.accountId, detail = "by ${phone.phoneId}")
        LinkCode(code.code, code.expiresAt.toString())
    }

    /** The phone signing [action] asks to join the account whose link code is [SignedAction.subject]. */
    @Synchronized
    fun joinAccount(action: SignedAction): JoinResult = store.transaction {
        val device = signedBy(action, ReferenceSigningScheme.ACTION_JOIN_ACCOUNT)
            ?: return@transaction JoinResult(false, "This phone isn't registered.")
        val phone = phoneOf(device)
        val code = store.linkCode(ReferenceSigningScheme.normalizeLinkCode(action.subject))
            ?.takeIf { it.expiresAt.isAfter(clock.instant()) && it.accountId != phone.accountId }
        if (code == null) {
            audit.record("join-refused", subject = phone.phoneId, detail = "code not valid")
            return@transaction JoinResult(false, "That code isn't valid. Make a new one on your other phone.")
        }
        // Single use: whoever saw the code can't use it again after this phone has.
        store.deleteLinkCode(code.code)
        store.putPhone(phone.copy(pendingAccountId = code.accountId))
        audit.record("join-requested", subject = code.accountId, detail = "by ${phone.phoneId}")
        JoinResult(true, "Now approve this phone on your other phone.")
    }

    /**
     * Before deciding about another phone, the deciding phone gets a one-time challenge bound to
     * that decision, and learns which key has to sign it: the step-up key when it has one.
     */
    @Synchronized
    fun decisionChallenge(request: DecisionChallengeRequest): DecisionChallenge? = store.transaction {
        val device = store.key(request.deviceKeyId)?.takeIf { it.role == KeyRole.DEVICE && !it.isRevoked } ?: return@transaction null
        decisionProblem(phoneOf(device), request.phoneId, request.action)?.let { return@transaction null }
        val hasStepUp = store.stepUpKeyOf(device.keyId) != null
        val confirmation = if (hasStepUp) RequiredConfirmation.STEP_UP_KEY else RequiredConfirmation.TAP
        val nonce = issueChallenge(ChallengePurpose.DECISION, device.keyId, confirmation, decisionHash(request.action, request.phoneId))
        DecisionChallenge(nonce, if (hasStepUp) KeyRole.STEP_UP else KeyRole.DEVICE, confirmation)
    }

    /** Approves or declines a phone waiting to join, or removes one from the account. */
    @Synchronized
    fun decide(decision: PhoneDecision): DecisionResult = store.transaction {
        fun refuse(reason: String): DecisionResult {
            audit.record("decision-refused", subject = decision.phoneId, detail = "${decision.action}: $reason")
            return DecisionResult(false, reason)
        }
        val key = store.key(decision.keyId)?.takeIf { !it.isRevoked } ?: return@transaction refuse("Unknown key")
        val device = store.key(key.deviceKeyId)?.takeIf { !it.isRevoked } ?: return@transaction refuse("Unknown phone")
        val challenge = challengeFor(decision.nonce, ChallengePurpose.DECISION, device.keyId, clock.instant())
            ?.takeIf { it.boundHash == decisionHash(decision.action, decision.phoneId) }
            ?: return@transaction refuse("This decision wasn't asked for, or took too long")
        val confirmed = when (challenge.confirmation) {
            RequiredConfirmation.STEP_UP_KEY -> key.role == KeyRole.STEP_UP
            RequiredConfirmation.TAP -> key.role == KeyRole.DEVICE && decision.tapConfirmed
            RequiredConfirmation.NONE -> false
        }
        if (!confirmed) return@transaction refuse("Not confirmed the way the server asked")
        val signature = ReferenceSigningScheme.decodeOrNull(decision.signature)
        val input = ReferenceSigningScheme.decisionInput(decision.action, decision.nonce, decision.phoneId, decision.tapConfirmed)
        if (signature == null || !verifySignature(key, input, signature)) return@transaction refuse("Signature doesn't match")
        val deciding = phoneOf(device)
        decisionProblem(deciding, decision.phoneId, decision.action)?.let { return@transaction refuse(it) }
        store.spendChallenge(decision.nonce, clock.instant())

        val other = checkNotNull(store.phone(decision.phoneId))
        val now = clock.instant()
        when (decision.action) {
            ReferenceSigningScheme.DECISION_APPROVE -> {
                store.putPhone(other.copy(accountId = deciding.accountId, joinedAt = now, pendingAccountId = null))
                audit.record("phone-approved", subject = deciding.accountId, detail = "${other.phoneId} by ${deciding.phoneId}")
                DecisionResult(true, "${other.label} can now use this account.")
            }
            ReferenceSigningScheme.DECISION_DECLINE -> {
                store.putPhone(other.copy(pendingAccountId = null))
                audit.record("join-declined", subject = deciding.accountId, detail = "${other.phoneId} by ${deciding.phoneId}")
                DecisionResult(true, "${other.label} wasn't let in.")
            }
            else -> {
                store.activeDeviceKey(other.phoneId)?.let { revokePhoneKeys(it, now, "Removed by ${deciding.phoneId}") }
                audit.record("phone-removed-from-account", subject = deciding.accountId, detail = "${other.phoneId} by ${deciding.phoneId}")
                DecisionResult(true, "${other.label} was removed and can't pay any more.")
            }
        }
    }

    /** Why [deciding] can't [action] the phone [phoneId], or null when it can. */
    private fun decisionProblem(deciding: StoredPhone, phoneId: String, action: String): String? {
        val other = store.phone(phoneId) ?: return "Unknown phone"
        if (isNewPhone(deciding, clock.instant())) return "A phone that's new on the account can't decide about others yet"
        return when (action) {
            ReferenceSigningScheme.DECISION_APPROVE, ReferenceSigningScheme.DECISION_DECLINE ->
                if (other.pendingAccountId != deciding.accountId) "That phone isn't waiting to join this account" else null
            ReferenceSigningScheme.DECISION_REMOVE -> when {
                other.accountId != deciding.accountId -> "That phone isn't on this account"
                other.phoneId == deciding.phoneId -> "A phone can't remove itself this way"
                else -> null
            }
            else -> "Unknown decision"
        }
    }

    /** The device key that signed [action] for [expected], with its challenge spent, or null. */
    private fun signedBy(action: SignedAction, expected: String): StoredKey? {
        val challenge = ReferenceSigningScheme.decodeOrNull(action.challenge) ?: return null
        val proof = ReferenceSigningScheme.decodeOrNull(action.proof) ?: return null
        val device = store.key(action.deviceKeyId)?.takeIf { it.role == KeyRole.DEVICE && !it.isRevoked } ?: return null
        if (!verifySignature(device, ReferenceSigningScheme.keyBindingInput(expected, challenge, action.subject), proof)) return null
        if (!spendRegistrationChallenge(challenge, action.deviceKeyId)) return null
        return device
    }

    private fun decisionHash(action: String, phoneId: String): String = ReferenceSigningScheme.sha256Hex("decide-phone\n$action\n$phoneId")

    private fun newLinkCode(): String =
        (1..LINK_CODE_LENGTH).map { ReferenceSigningScheme.LINK_CODE_ALPHABET[random.nextInt(ReferenceSigningScheme.LINK_CODE_ALPHABET.length)] }
            .joinToString("")

    private fun newId(prefix: String): String = prefix + ReferenceSigningScheme.hex(ByteArray(8).also(random::nextBytes))

    private fun cleanLabel(label: String?): String =
        label?.filter { it.isLetterOrDigit() || it in " -_.()" }?.trim()?.take(40)?.ifBlank { null } ?: "Phone"

    /** Checks a signed request against a verification challenge and spends it, charging nothing. */
    @Synchronized
    fun authenticate(request: ReceivedRequest, receivedAt: Instant = clock.instant()): VerificationResult = store.transaction {
        check(request, receivedAt).also { result ->
            val subject = request.header(ReferenceSigningScheme.HEADER_KEY_ID)?.let(store::key)?.phoneId ?: "unknown"
            audit.record("request-checked", subject, if (result is VerificationResult.Rejected) "refused: ${result.reason.name.lowercase()}" else "accepted")
        }
    }

    private fun check(request: ReceivedRequest, receivedAt: Instant): VerificationResult {
        val key = when (val check = checkSignature(request, receivedAt)) {
            is SignatureCheck.Failed -> return VerificationResult.Rejected(check.reason)
            is SignatureCheck.Passed -> check.key
        }
        val nonce = request.header(ReferenceSigningScheme.HEADER_NONCE).orEmpty()
        challengeFor(nonce, ChallengePurpose.VERIFICATION, key.deviceKeyId, receivedAt)
            ?: return VerificationResult.Rejected(missingChallengeReason(nonce))
        store.spendChallenge(nonce, receivedAt)
        return VerificationResult.Accepted
    }

    /**
     * Charges at most once per idempotency key. A request repeated after a lost response gets the
     * original result back, even though its challenge was spent the first time.
     */
    @Synchronized
    fun submitPayment(request: ReceivedRequest, receivedAt: Instant = clock.instant()): PaymentResponse = store.transaction {
        pay(request, receivedAt).also { response ->
            val subject = request.header(ReferenceSigningScheme.HEADER_KEY_ID)?.let(store::key)?.phoneId ?: "unknown"
            when (response) {
                is PaymentResponse.Processed -> audit.record(
                    if (response.replayed) "payment-repeated" else "payment-charged",
                    subject,
                    "${response.payment.id} ${response.payment.amountMinor} ${response.payment.currency}",
                )
                is PaymentResponse.Rejected -> audit.record("payment-refused", subject, response.reason.name.lowercase())
            }
        }
    }

    private fun pay(request: ReceivedRequest, receivedAt: Instant): PaymentResponse {
        val key = when (val check = checkSignature(request, receivedAt)) {
            is SignatureCheck.Failed -> return PaymentResponse.Rejected(check.reason)
            is SignatureCheck.Passed -> check.key
        }
        val idempotencyKey = request.header(ReferenceSigningScheme.HEADER_IDEMPOTENCY_KEY)
            ?.takeIf { it.isNotBlank() }
            ?: return PaymentResponse.Rejected(RejectionReason.MISSING_HEADERS)
        val fingerprint = listOf(request.path, ReferenceSigningScheme.sha256Hex(request.body)).joinToString("|")

        // Scoped to the device, so one device's keys can't collide with or probe another's.
        store.ledgerEntry(key.deviceKeyId, idempotencyKey)?.let { entry ->
            return if (entry.fingerprint == fingerprint) {
                PaymentResponse.Processed(entry.payment, replayed = true)
            } else {
                PaymentResponse.Rejected(RejectionReason.IDEMPOTENCY_CONFLICT)
            }
        }

        val payload = runCatching { PaymentBody.read(request.body) }.getOrNull()
            ?.takeIf { it.amountMinor > 0 && it.currency.isNotBlank() }
            ?: return PaymentResponse.Rejected(RejectionReason.MALFORMED_BODY)

        val nonce = request.header(ReferenceSigningScheme.HEADER_NONCE).orEmpty()
        val challenge = challengeFor(nonce, ChallengePurpose.PAYMENT, key.deviceKeyId, receivedAt)
            ?: return PaymentResponse.Rejected(missingChallengeReason(nonce))
        // What was authorized is what gets paid: approving a small payment can't carry a large one.
        if (challenge.boundHash != null && challenge.boundHash != ReferenceSigningScheme.sha256Hex(canonical.canonicalize(payload))) {
            return PaymentResponse.Rejected(RejectionReason.PAYMENT_CHANGED)
        }
        val confirmed = when (challenge.confirmation) {
            RequiredConfirmation.NONE -> key.role == KeyRole.DEVICE
            RequiredConfirmation.STEP_UP_KEY -> key.role == KeyRole.STEP_UP
            RequiredConfirmation.TAP -> key.role == KeyRole.DEVICE &&
                request.header(ReferenceSigningScheme.HEADER_CONFIRMATION) == ReferenceSigningScheme.CONFIRMATION_TAP
        }
        if (!confirmed) return PaymentResponse.Rejected(RejectionReason.CONFIRMATION_REQUIRED)
        store.spendChallenge(nonce, receivedAt)
        // Checked when charging, so authorizations collected in advance can't add up past the limits.
        val deviceKey = store.key(key.deviceKeyId) ?: return PaymentResponse.Rejected(RejectionReason.UNKNOWN_KEY)
        limitBroken(deviceKey, payload.amountMinor, receivedAt)?.let { return PaymentResponse.Rejected(it) }

        val payment = Payment(
            id = "PAY-" + ReferenceSigningScheme.sha256Hex(nonce + idempotencyKey).take(8).uppercase(),
            amountMinor = payload.amountMinor,
            currency = payload.currency,
            signedWith = key.role,
            confirmation = challenge.confirmation,
            processedAt = receivedAt.toString(),
            payee = payload.payee,
        )
        store.putLedgerEntry(key.deviceKeyId, idempotencyKey, LedgerEntry(fingerprint, payment))
        return PaymentResponse.Processed(payment, replayed = false)
    }

    private sealed interface SignatureCheck {
        class Passed(val key: StoredKey) : SignatureCheck

        class Failed(val reason: RejectionReason) : SignatureCheck
    }

    private fun checkSignature(request: ReceivedRequest, receivedAt: Instant): SignatureCheck {
        val timestamp = request.header(ReferenceSigningScheme.HEADER_TIMESTAMP)
        val nonce = request.header(ReferenceSigningScheme.HEADER_NONCE)
        val keyId = request.header(ReferenceSigningScheme.HEADER_KEY_ID)
        val signature = request.header(ReferenceSigningScheme.HEADER_SIGNATURE)
        val idempotencyKey = request.header(ReferenceSigningScheme.HEADER_IDEMPOTENCY_KEY)
        val confirmation = request.header(ReferenceSigningScheme.HEADER_CONFIRMATION)
        if (timestamp.isNullOrBlank() || nonce.isNullOrBlank() || keyId.isNullOrBlank() || signature.isNullOrBlank()) {
            return SignatureCheck.Failed(RejectionReason.MISSING_HEADERS)
        }
        // The signed fields are joined with line breaks, so a value containing one could shift the others.
        if (listOfNotNull(timestamp, nonce, keyId, idempotencyKey, confirmation).any { '\n' in it }) {
            return SignatureCheck.Failed(RejectionReason.MISSING_HEADERS)
        }
        val signedAt = try {
            Instant.parse(timestamp)
        } catch (_: DateTimeParseException) {
            return SignatureCheck.Failed(RejectionReason.MALFORMED_TIMESTAMP)
        }
        if (Duration.between(signedAt, receivedAt).abs() > ReferenceSigningScheme.TIME_WINDOW) {
            return SignatureCheck.Failed(RejectionReason.OUTSIDE_TIME_WINDOW)
        }
        val key = store.key(keyId) ?: return SignatureCheck.Failed(RejectionReason.UNKNOWN_KEY)
        if (key.isRevoked) return SignatureCheck.Failed(RejectionReason.KEY_REVOKED)
        val input = ReferenceSigningScheme.signingInput(
            method = request.method,
            path = request.path,
            timestamp = timestamp,
            nonce = nonce,
            keyId = keyId,
            idempotencyKey = idempotencyKey,
            confirmation = confirmation,
            bodyHash = ReferenceSigningScheme.sha256Hex(request.body),
        )
        val presented = ReferenceSigningScheme.decodeOrNull(signature)
            ?: return SignatureCheck.Failed(RejectionReason.SIGNATURE_MISMATCH)
        return if (verifySignature(key, input, presented)) {
            SignatureCheck.Passed(key)
        } else {
            SignatureCheck.Failed(RejectionReason.SIGNATURE_MISMATCH)
        }
    }

    private fun verifySignature(key: StoredKey, data: ByteArray, signature: ByteArray): Boolean = runCatching {
        Signature.getInstance(ReferenceSigningScheme.SIGNATURE_ALGORITHM).run {
            initVerify(checkNotNull(decodePublicKey(key.encodedPublicKey)))
            update(data)
            verify(signature)
        }
    }.getOrDefault(false)

    /**
     * The live challenge [nonce] names, if it was issued for [purpose] to [deviceKeyId]. Nothing is
     * spent, so a request that fails a later check can't burn a genuine request's challenge.
     */
    private fun challengeFor(nonce: String, purpose: ChallengePurpose, deviceKeyId: String?, at: Instant): StoredChallenge? {
        // Spent nonces are kept only to tell a replay from an unknown nonce; removing a spent
        // challenge from the live set is what refuses the replay.
        store.prune(
            challengesExpiredBefore = at.minus(ReferenceSigningScheme.TIME_WINDOW),
            spentBefore = at.minus(CHALLENGE_LIFETIME.plus(ReferenceSigningScheme.TIME_WINDOW.multipliedBy(2))),
        )
        return store.challenge(nonce)?.takeIf {
            it.purpose == purpose && it.deviceKeyId == deviceKeyId && !it.expiresAt.isBefore(at)
        }
    }

    private fun missingChallengeReason(nonce: String): RejectionReason =
        if (store.isSpent(nonce)) RejectionReason.CHALLENGE_REUSED else RejectionReason.UNKNOWN_CHALLENGE

    private fun spendRegistrationChallenge(challenge: ByteArray, deviceKeyId: String?): Boolean {
        val nonce = ReferenceSigningScheme.encode(challenge)
        val now = clock.instant()
        challengeFor(nonce, ChallengePurpose.REGISTRATION, deviceKeyId, now) ?: return false
        store.spendChallenge(nonce, now)
        return true
    }

    private fun issueChallenge(
        purpose: ChallengePurpose,
        deviceKeyId: String,
        confirmation: RequiredConfirmation,
        boundHash: String? = null,
    ): String {
        val nonce = ReferenceSigningScheme.hex(ByteArray(16).also(random::nextBytes))
        store.putChallenge(StoredChallenge(nonce, purpose, deviceKeyId, confirmation, clock.instant().plus(CHALLENGE_LIFETIME), boundHash))
        return nonce
    }

    private fun decodePublicKey(encoded: ByteArray): PublicKey? = runCatching {
        KeyFactory.getInstance(ReferenceSigningScheme.KEY_ALGORITHM).generatePublic(X509EncodedKeySpec(encoded))
    }.getOrNull()

    private companion object {
        val CHALLENGE_LIFETIME: Duration = Duration.ofMinutes(5)
        val LINK_CODE_LIFETIME: Duration = Duration.ofMinutes(10)

        /** 31 symbols over 8 places: about 8.5 × 10¹¹ codes, each valid once for ten minutes, behind rate limits. */
        const val LINK_CODE_LENGTH = 8
    }
}

/** Reads a payment body strictly: an unexpected field is a request the backend doesn't understand. */
private object PaymentBody {
    private val json = Json { ignoreUnknownKeys = false }

    fun read(body: String): PaymentRequestPayload = json.decodeFromString(PaymentRequestPayload.serializer(), body)
}

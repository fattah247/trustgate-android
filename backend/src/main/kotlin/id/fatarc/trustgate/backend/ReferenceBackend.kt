package id.fatarc.trustgate.backend

import id.fatarc.trustgate.backend.attestation.AttestationPolicy
import id.fatarc.trustgate.backend.attestation.KeyAttestationVerifier
import id.fatarc.trustgate.backend.attestation.RevocationList
import id.fatarc.trustgate.backend.store.BackendStore
import id.fatarc.trustgate.backend.store.ChallengePurpose
import id.fatarc.trustgate.backend.store.InMemoryBackendStore
import id.fatarc.trustgate.backend.store.LedgerEntry
import id.fatarc.trustgate.backend.store.StoredChallenge
import id.fatarc.trustgate.backend.store.StoredKey
import id.fatarc.trustgate.backend.attestation.toSummary
import id.fatarc.trustgate.domain.actiongate.SensitiveActionDecision
import id.fatarc.trustgate.domain.actiongate.SensitiveActionGate
import id.fatarc.trustgate.domain.api.Payment
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.PaymentResponse
import id.fatarc.trustgate.domain.api.RegistrationResult
import id.fatarc.trustgate.domain.api.RequiredConfirmation
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.PaymentRequestPayload
import id.fatarc.trustgate.domain.signing.ReceivedRequest
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
    private val policy: AttestationPolicy,
    private val clock: Clock = Clock.systemUTC(),
    /** The latest copy of Google's status list; the server refreshes it in the background. */
    private val revocations: () -> RevocationList? = { RevocationList.EMPTY },
    private val store: BackendStore = InMemoryBackendStore(),
) {
    private val gate = SensitiveActionGate()
    private val random = SecureRandom()

    /** How many payments were actually charged, however many requests arrived. */
    val chargedPayments: Int @Synchronized get() = store.transaction { store.ledgerSize() }

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
    ): RegistrationResult = store.transaction {
        register(role, encodedPublicKey, attestationChain, challenge, deviceKeyId, deviceKeyProof)
    }

    private fun register(
        role: KeyRole,
        encodedPublicKey: ByteArray,
        attestationChain: List<ByteArray>,
        challenge: ByteArray,
        deviceKeyId: String?,
        deviceKeyProof: ByteArray?,
    ): RegistrationResult {
        if (!spendRegistrationChallenge(challenge, deviceKeyId)) {
            return RegistrationResult.Refused("The registration challenge doesn't match this request, or has expired.")
        }
        decodePublicKey(encodedPublicKey) ?: return RegistrationResult.Refused("The public key couldn't be read.")
        val keyId = ReferenceSigningScheme.keyIdFor(encodedPublicKey)
        if (store.key(keyId) != null) return RegistrationResult.Refused("This key is already registered.")

        val attestation = KeyAttestationVerifier.verify(attestationChain, encodedPublicKey, challenge)
        policy.problemWith(attestation, revocations())?.let { return RegistrationResult.Refused(it) }

        fun stored(owner: String) = StoredKey(
            keyId = keyId,
            role = role,
            encodedPublicKey = encodedPublicKey,
            deviceKeyId = owner,
            attested = attestation.isAttested,
            rootKeyFingerprint = attestation.rootKeyFingerprint,
            registeredAt = clock.instant(),
        )
        when (role) {
            KeyRole.DEVICE -> {
                if (deviceKeyId != null) return RegistrationResult.Refused("A device key can't belong to another key.")
                store.putKey(stored(owner = keyId))
            }

            KeyRole.STEP_UP -> {
                val owner = deviceKeyId?.let(store::key)?.takeIf { it.role == KeyRole.DEVICE }
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
                store.putKey(stored(owner = owner.keyId))
                store.setStepUpKey(owner.keyId, keyId)
            }
        }
        return RegistrationResult.Registered(keyId, role, attestation.toSummary(trustedRoot = policy.trustsRoot(attestation)))
    }

    /**
     * Drops a device's step-up key when its screen lock is gone, so medium risk falls back to a tap.
     * The device key must sign the request, or anyone who knew its key ID could downgrade it.
     */
    @Synchronized
    fun removeStepUpKey(deviceKeyId: String, challenge: ByteArray, deviceKeyProof: ByteArray): Boolean = store.transaction {
        if (!spendRegistrationChallenge(challenge, deviceKeyId)) return@transaction false
        val owner = store.key(deviceKeyId)?.takeIf { it.role == KeyRole.DEVICE } ?: return@transaction false
        val vouched = verifySignature(
            owner,
            ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_REMOVE_STEP_UP, challenge, deviceKeyId),
            deviceKeyProof,
        )
        if (!vouched) return@transaction false
        store.stepUpKeyOf(deviceKeyId)?.let(store::deleteKey)
        store.setStepUpKey(deviceKeyId, null)
        true
    }

    /** A one-time challenge for signing a request only to have it checked, with nothing charged. */
    @Synchronized
    fun issueVerificationChallenge(deviceKeyId: String): String = store.transaction {
        issueChallenge(ChallengePurpose.VERIFICATION, deviceKeyId, RequiredConfirmation.NONE)
    }

    /**
     * Decides whether a protected action may run, here rather than in the app, and hands back the
     * challenge the request must sign together with the key it must be signed with. [level] is what
     * the device reports about itself; a production backend derives it from a Play Integrity verdict.
     */
    @Synchronized
    fun beginPayment(deviceKeyId: String, level: DeviceRiskLevel): PaymentAuthorization = store.transaction {
        when (val decision = gate.decide(level)) {
            SensitiveActionDecision.BLOCK -> PaymentAuthorization.Blocked(level)
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
                val nonce = issueChallenge(ChallengePurpose.PAYMENT, deviceKeyId, confirmation)
                PaymentAuthorization.Proceed(decision, nonce, signWith, confirmation)
            }
        }
    }

    /** Checks a signed request against a verification challenge and spends it, charging nothing. */
    @Synchronized
    fun authenticate(request: ReceivedRequest, receivedAt: Instant = clock.instant()): VerificationResult = store.transaction {
        val key = when (val check = checkSignature(request, receivedAt)) {
            is SignatureCheck.Failed -> return@transaction VerificationResult.Rejected(check.reason)
            is SignatureCheck.Passed -> check.key
        }
        val nonce = request.header(ReferenceSigningScheme.HEADER_NONCE).orEmpty()
        challengeFor(nonce, ChallengePurpose.VERIFICATION, key.deviceKeyId, receivedAt)
            ?: return@transaction VerificationResult.Rejected(missingChallengeReason(nonce))
        store.spendChallenge(nonce, receivedAt)
        VerificationResult.Accepted
    }

    /**
     * Charges at most once per idempotency key. A request repeated after a lost response gets the
     * original result back, even though its challenge was spent the first time.
     */
    @Synchronized
    fun submitPayment(request: ReceivedRequest, receivedAt: Instant = clock.instant()): PaymentResponse = store.transaction {
        pay(request, receivedAt)
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
        val confirmed = when (challenge.confirmation) {
            RequiredConfirmation.NONE -> key.role == KeyRole.DEVICE
            RequiredConfirmation.STEP_UP_KEY -> key.role == KeyRole.STEP_UP
            RequiredConfirmation.TAP -> key.role == KeyRole.DEVICE &&
                request.header(ReferenceSigningScheme.HEADER_CONFIRMATION) == ReferenceSigningScheme.CONFIRMATION_TAP
        }
        if (!confirmed) return PaymentResponse.Rejected(RejectionReason.CONFIRMATION_REQUIRED)
        store.spendChallenge(nonce, receivedAt)

        val payment = Payment(
            id = "PAY-" + ReferenceSigningScheme.sha256Hex(nonce + idempotencyKey).take(8).uppercase(),
            amountMinor = payload.amountMinor,
            currency = payload.currency,
            signedWith = key.role,
            confirmation = challenge.confirmation,
            processedAt = receivedAt.toString(),
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

    private fun issueChallenge(purpose: ChallengePurpose, deviceKeyId: String, confirmation: RequiredConfirmation): String {
        val nonce = ReferenceSigningScheme.hex(ByteArray(16).also(random::nextBytes))
        store.putChallenge(StoredChallenge(nonce, purpose, deviceKeyId, confirmation, clock.instant().plus(CHALLENGE_LIFETIME)))
        return nonce
    }

    private fun decodePublicKey(encoded: ByteArray): PublicKey? = runCatching {
        KeyFactory.getInstance(ReferenceSigningScheme.KEY_ALGORITHM).generatePublic(X509EncodedKeySpec(encoded))
    }.getOrNull()

    private companion object {
        val CHALLENGE_LIFETIME: Duration = Duration.ofMinutes(5)
    }
}

/** Reads a payment body strictly: an unexpected field is a request the backend doesn't understand. */
private object PaymentBody {
    private val json = Json { ignoreUnknownKeys = false }

    fun read(body: String): PaymentRequestPayload = json.decodeFromString(PaymentRequestPayload.serializer(), body)
}

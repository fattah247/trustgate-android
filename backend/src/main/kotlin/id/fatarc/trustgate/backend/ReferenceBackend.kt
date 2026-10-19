package id.fatarc.trustgate.backend

import id.fatarc.trustgate.backend.attestation.AttestationReport
import id.fatarc.trustgate.backend.attestation.KeyAttestationVerifier
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
 * makes the gate decision, and processes payments idempotently.
 */
class ReferenceBackend(
    private val clock: Clock = Clock.systemUTC(),
) {
    private val gate = SensitiveActionGate()
    private val random = SecureRandom()

    private class KeyEntry(
        val keyId: String,
        val role: KeyRole,
        val publicKey: PublicKey,
        /** The device key this key belongs to; a device key belongs to itself. */
        val deviceKeyId: String,
        val attestation: AttestationReport,
    )

    private enum class Purpose { REGISTRATION, VERIFICATION, PAYMENT }

    private class Challenge(
        val purpose: Purpose,
        /** The device the challenge was issued to; null only for registering a new device key. */
        val deviceKeyId: String?,
        val confirmation: RequiredConfirmation,
        val expiresAt: Instant,
    )

    private class LedgerEntry(val fingerprint: String, val payment: Payment)

    private val keys = HashMap<String, KeyEntry>()
    private val stepUpKeyFor = HashMap<String, String>()
    private val outstanding = HashMap<String, Challenge>()
    private val used = HashMap<String, Instant>()
    private val ledger = HashMap<String, LedgerEntry>()

    /** How many payments were actually charged, however many requests arrived. */
    val chargedPayments: Int @Synchronized get() = ledger.size

    /**
     * A one-time registration challenge. Pass [deviceKeyId] to add or remove that device's step-up
     * key; those operations also need a signature from the device key.
     */
    @Synchronized
    fun issueRegistrationChallenge(deviceKeyId: String? = null): ByteArray {
        val bytes = ByteArray(32).also(random::nextBytes)
        outstanding[ReferenceSigningScheme.encode(bytes)] = Challenge(
            purpose = Purpose.REGISTRATION,
            deviceKeyId = deviceKeyId,
            confirmation = RequiredConfirmation.NONE,
            expiresAt = clock.instant().plus(CHALLENGE_LIFETIME),
        )
        return bytes
    }

    /**
     * Registers a key from its certificate chain. A chain that doesn't verify, certifies another key,
     * or carries another challenge is refused. Only a key's own self-signed certificate, which is what
     * Keystore returns without attestation support, is accepted as unattested.
     *
     * A step-up key must be vouched for by its device: [deviceKeyProof] is the device key's
     * signature over [ReferenceSigningScheme.keyBindingInput] for this challenge and key.
     */
    @Synchronized
    fun registerKey(
        role: KeyRole,
        encodedPublicKey: ByteArray,
        attestationChain: List<ByteArray>,
        challenge: ByteArray,
        deviceKeyId: String? = null,
        deviceKeyProof: ByteArray? = null,
    ): RegistrationResult {
        if (!spendRegistrationChallenge(challenge, deviceKeyId)) {
            return RegistrationResult.Refused("The registration challenge doesn't match this request, or has expired.")
        }

        val publicKey = decodePublicKey(encodedPublicKey)
            ?: return RegistrationResult.Refused("The public key couldn't be read.")
        val keyId = ReferenceSigningScheme.keyIdFor(encodedPublicKey)
        if (keyId in keys) return RegistrationResult.Refused("This key is already registered.")

        val attestation = KeyAttestationVerifier.verify(attestationChain, encodedPublicKey, challenge)
        attestationProblem(attestation)?.let { return RegistrationResult.Refused(it) }

        when (role) {
            KeyRole.DEVICE -> {
                if (deviceKeyId != null) return RegistrationResult.Refused("A device key can't belong to another key.")
                keys[keyId] = KeyEntry(keyId, role, publicKey, deviceKeyId = keyId, attestation = attestation)
            }

            KeyRole.STEP_UP -> {
                val owner = deviceKeyId?.let(keys::get)?.takeIf { it.role == KeyRole.DEVICE }
                    ?: return RegistrationResult.Refused("A step-up key needs a registered device key.")
                val vouched = deviceKeyProof != null && verifySignature(
                    owner.publicKey,
                    ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_ADD_STEP_UP, challenge, keyId),
                    deviceKeyProof,
                )
                if (!vouched) return RegistrationResult.Refused("The device key didn't vouch for this step-up key.")
                if (owner.attestation.isAttested) {
                    if (!attestation.isAttested) return RegistrationResult.Refused("An attested device needs an attested step-up key.")
                    if (attestation.rootKeyFingerprint != owner.attestation.rootKeyFingerprint) {
                        return RegistrationResult.Refused("The step-up key was attested by a different root than the device key.")
                    }
                }
                // A step-up key whose attestation says it signs without authentication isn't a step-up key.
                if (attestation.isAttested && attestation.description?.userAuthRequired != true) {
                    return RegistrationResult.Refused("The attestation shows this key doesn't require authentication.")
                }
                stepUpKeyFor[owner.keyId]?.let(keys::remove)
                keys[keyId] = KeyEntry(keyId, role, publicKey, deviceKeyId = owner.keyId, attestation = attestation)
                stepUpKeyFor[owner.keyId] = keyId
            }
        }
        return RegistrationResult.Registered(keyId, role, attestation.toSummary())
    }

    /**
     * Drops a device's step-up key when its screen lock is gone, so medium risk falls back to a tap.
     * The device key must sign the request, or anyone who knew its key ID could downgrade it.
     */
    @Synchronized
    fun removeStepUpKey(deviceKeyId: String, challenge: ByteArray, deviceKeyProof: ByteArray): Boolean {
        if (!spendRegistrationChallenge(challenge, deviceKeyId)) return false
        val owner = keys[deviceKeyId]?.takeIf { it.role == KeyRole.DEVICE } ?: return false
        val vouched = verifySignature(
            owner.publicKey,
            ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_REMOVE_STEP_UP, challenge, deviceKeyId),
            deviceKeyProof,
        )
        if (!vouched) return false
        stepUpKeyFor.remove(deviceKeyId)?.let(keys::remove)
        return true
    }

    /** A one-time challenge for signing a request only to have it checked, with nothing charged. */
    @Synchronized
    fun issueVerificationChallenge(deviceKeyId: String): String =
        issueChallenge(Purpose.VERIFICATION, deviceKeyId, RequiredConfirmation.NONE)

    /**
     * Decides whether a protected action may run, here rather than in the app, and hands back the
     * challenge the request must sign together with the key it must be signed with. [level] is what
     * the device reports about itself; a production backend derives it from a Play Integrity verdict.
     */
    @Synchronized
    fun beginPayment(deviceKeyId: String, level: DeviceRiskLevel): PaymentAuthorization {
        return when (val decision = gate.decide(level)) {
            SensitiveActionDecision.BLOCK -> PaymentAuthorization.Blocked(level)
            SensitiveActionDecision.ALLOW,
            SensitiveActionDecision.REQUIRE_CONFIRMATION,
            -> {
                val stepUp = decision == SensitiveActionDecision.REQUIRE_CONFIRMATION
                val hasStepUpKey = stepUpKeyFor.containsKey(deviceKeyId)
                val signWith = if (stepUp && hasStepUpKey) KeyRole.STEP_UP else KeyRole.DEVICE
                val confirmation = when {
                    !stepUp -> RequiredConfirmation.NONE
                    hasStepUpKey -> RequiredConfirmation.STEP_UP_KEY
                    else -> RequiredConfirmation.TAP
                }
                val nonce = issueChallenge(Purpose.PAYMENT, deviceKeyId, confirmation)
                PaymentAuthorization.Proceed(decision, nonce, signWith, confirmation)
            }
        }
    }

    /** Checks a signed request against a verification challenge and spends it, charging nothing. */
    @Synchronized
    fun authenticate(request: ReceivedRequest, receivedAt: Instant = clock.instant()): VerificationResult {
        val key = when (val check = checkSignature(request, receivedAt)) {
            is SignatureCheck.Failed -> return VerificationResult.Rejected(check.reason)
            is SignatureCheck.Passed -> check.key
        }
        val nonce = request.header(ReferenceSigningScheme.HEADER_NONCE).orEmpty()
        challengeFor(nonce, Purpose.VERIFICATION, key.deviceKeyId, receivedAt)
            ?: return VerificationResult.Rejected(missingChallengeReason(nonce))
        spend(nonce, receivedAt)
        return VerificationResult.Accepted
    }

    /**
     * Charges at most once per idempotency key. A request repeated after a lost response gets the
     * original result back, even though its challenge was spent the first time.
     */
    @Synchronized
    fun submitPayment(request: ReceivedRequest, receivedAt: Instant = clock.instant()): PaymentResponse {
        val key = when (val check = checkSignature(request, receivedAt)) {
            is SignatureCheck.Failed -> return PaymentResponse.Rejected(check.reason)
            is SignatureCheck.Passed -> check.key
        }
        val idempotencyKey = request.header(ReferenceSigningScheme.HEADER_IDEMPOTENCY_KEY)
            ?.takeIf { it.isNotBlank() }
            ?: return PaymentResponse.Rejected(RejectionReason.MISSING_HEADERS)
        // Scoped to the device, so one device's keys can't collide with or probe another's.
        val ledgerKey = key.deviceKeyId + ":" + idempotencyKey
        val fingerprint = listOf(request.path, ReferenceSigningScheme.sha256Hex(request.body)).joinToString("|")

        ledger[ledgerKey]?.let { entry ->
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
        val challenge = challengeFor(nonce, Purpose.PAYMENT, key.deviceKeyId, receivedAt)
            ?: return PaymentResponse.Rejected(missingChallengeReason(nonce))
        val confirmed = when (challenge.confirmation) {
            RequiredConfirmation.NONE -> key.role == KeyRole.DEVICE
            RequiredConfirmation.STEP_UP_KEY -> key.role == KeyRole.STEP_UP
            RequiredConfirmation.TAP -> key.role == KeyRole.DEVICE &&
                request.header(ReferenceSigningScheme.HEADER_CONFIRMATION) == ReferenceSigningScheme.CONFIRMATION_TAP
        }
        if (!confirmed) return PaymentResponse.Rejected(RejectionReason.CONFIRMATION_REQUIRED)
        spend(nonce, receivedAt)

        val payment = Payment(
            id = "PAY-" + ReferenceSigningScheme.sha256Hex(nonce + idempotencyKey).take(8).uppercase(),
            amountMinor = payload.amountMinor,
            currency = payload.currency,
            signedWith = key.role,
            confirmation = challenge.confirmation,
            processedAt = receivedAt.toString(),
        )
        ledger[ledgerKey] = LedgerEntry(fingerprint, payment)
        return PaymentResponse.Processed(payment, replayed = false)
    }

    private sealed interface SignatureCheck {
        class Passed(val key: KeyEntry) : SignatureCheck

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
        val key = keys[keyId] ?: return SignatureCheck.Failed(RejectionReason.UNKNOWN_KEY)
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
        return if (verifySignature(key.publicKey, input, presented)) {
            SignatureCheck.Passed(key)
        } else {
            SignatureCheck.Failed(RejectionReason.SIGNATURE_MISMATCH)
        }
    }

    private fun verifySignature(publicKey: PublicKey, data: ByteArray, signature: ByteArray): Boolean = runCatching {
        Signature.getInstance(ReferenceSigningScheme.SIGNATURE_ALGORITHM).run {
            initVerify(publicKey)
            update(data)
            verify(signature)
        }
    }.getOrDefault(false)

    /** Why a presented certificate chain can't be accepted, or null when it can. */
    private fun attestationProblem(report: AttestationReport): String? = when {
        report.chainLength == 0 -> "The key came without a certificate chain."
        !report.wellFormed -> "The attestation chain couldn't be read."
        report.isAttested && !report.chainSignaturesValid -> "The attestation chain doesn't verify."
        report.isAttested && !report.leafMatchesKey -> "The attestation certifies a different key."
        report.isAttested && !report.challengeMatches -> "The attestation was made for another challenge."
        report.isAttested -> null
        // Without attestation support, Keystore returns only the key's own self-signed certificate.
        report.chainLength == 1 && report.leafMatchesKey && report.chainSignaturesValid -> null
        else -> "The certificate chain carries no attestation for this key."
    }

    /**
     * The live challenge [nonce] names, if it was issued for [purpose] to [deviceKeyId]. Nothing is
     * spent, so a request that fails a later check can't burn a genuine request's challenge.
     */
    private fun challengeFor(nonce: String, purpose: Purpose, deviceKeyId: String?, at: Instant): Challenge? {
        prune(at)
        return outstanding[nonce]?.takeIf {
            it.purpose == purpose && it.deviceKeyId == deviceKeyId && !it.expiresAt.isBefore(at)
        }
    }

    private fun spend(nonce: String, at: Instant) {
        outstanding.remove(nonce)
        used[nonce] = at
    }

    private fun missingChallengeReason(nonce: String): RejectionReason =
        if (nonce in used) RejectionReason.CHALLENGE_REUSED else RejectionReason.UNKNOWN_CHALLENGE

    private fun spendRegistrationChallenge(challenge: ByteArray, deviceKeyId: String?): Boolean {
        val nonce = ReferenceSigningScheme.encode(challenge)
        val now = clock.instant()
        challengeFor(nonce, Purpose.REGISTRATION, deviceKeyId, now) ?: return false
        spend(nonce, now)
        return true
    }

    private fun issueChallenge(purpose: Purpose, deviceKeyId: String, confirmation: RequiredConfirmation): String {
        val nonce = ReferenceSigningScheme.hex(ByteArray(16).also(random::nextBytes))
        outstanding[nonce] = Challenge(purpose, deviceKeyId, confirmation, clock.instant().plus(CHALLENGE_LIFETIME))
        return nonce
    }

    /**
     * Removing a spent challenge from [outstanding] is what refuses a replay; [used] only remembers
     * it long enough to say so instead of calling it unknown.
     */
    private fun prune(now: Instant) {
        outstanding.entries.removeAll { it.value.expiresAt.isBefore(now.minus(ReferenceSigningScheme.TIME_WINDOW)) }
        used.entries.removeAll { it.value.isBefore(now.minus(CHALLENGE_LIFETIME.plus(ReferenceSigningScheme.TIME_WINDOW.multipliedBy(2)))) }
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

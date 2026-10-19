package id.fatarc.trustgate.core.keys

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import id.fatarc.trustgate.domain.api.SecurityLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Generates P-256 signing keys in Android Keystore. The private keys never leave secure hardware
 * when the device has it, and the step-up key refuses to sign until the person authenticates.
 */
class AndroidDeviceKeyProvider(
    context: Context,
) : DeviceKeyProvider {
    private val appContext = context.applicationContext
    private val keyStore: KeyStore by lazy { KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) } }

    override fun stepUpSupport(): StepUpSupport {
        val keyguard = appContext.getSystemService(KeyguardManager::class.java)
        if (keyguard?.isDeviceSecure != true) {
            return StepUpSupport.Unavailable("Set a screen lock to use it.")
        }
        // Before Android 11 a key can only be bound to biometrics per use, not to the screen lock.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R &&
            BiometricManager.from(appContext).canAuthenticate(BIOMETRIC_STRONG) != BiometricManager.BIOMETRIC_SUCCESS
        ) {
            return StepUpSupport.Unavailable("Add a fingerprint to use it on this Android version.")
        }
        return StepUpSupport.Available
    }

    override fun generate(role: KeyRole, attestationChallenge: ByteArray): GeneratedKey {
        delete(role)
        val alias = role.alias
        val preferStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            appContext.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        val attempts = buildList {
            if (preferStrongBox) add(KeyPlacement(strongBox = true, attested = true))
            add(KeyPlacement(strongBox = false, attested = true))
            // Some devices can't attest at all. The backend registers such a key as unattested.
            add(KeyPlacement(strongBox = false, attested = false))
        }
        var lastFailure: Exception? = null
        val placement = attempts.firstOrNull { placement ->
            try {
                generateKeyPair(role, attestationChallenge.takeIf { placement.attested }, placement.strongBox)
                true
            } catch (error: ProviderException) {
                // StrongBoxUnavailableException is a ProviderException, and so are attestation failures.
                lastFailure = error
                false
            } catch (error: InvalidAlgorithmParameterException) {
                lastFailure = error
                false
            }
        } ?: throw checkNotNull(lastFailure)

        val chain = keyStore.getCertificateChain(alias)?.map { it.encoded }.orEmpty()
        val publicKey = keyStore.getCertificate(alias).publicKey.encoded
        val protection = protectionOf(privateKey(role))
        return GeneratedKey(
            role = role,
            encodedPublicKey = publicKey,
            attestationChain = chain,
            // Before Android 12, KeyInfo can only say "secure hardware", so a StrongBox key reads as the TEE.
            protection = if (placement.strongBox && protection == SecurityLevel.TRUSTED_ENVIRONMENT) {
                SecurityLevel.STRONGBOX
            } else {
                protection
            },
        )
    }

    override fun delete(role: KeyRole) {
        if (keyStore.containsAlias(role.alias)) keyStore.deleteEntry(role.alias)
    }

    override fun hasKey(role: KeyRole): Boolean = keyStore.containsAlias(role.alias)

    override fun signWithDeviceKey(data: ByteArray): ByteArray =
        Signature.getInstance(ReferenceSigningScheme.SIGNATURE_ALGORITHM).run {
            initSign(privateKey(KeyRole.DEVICE))
            update(data)
            sign()
        }

    override fun stepUpSignature(): Signature {
        val key = try {
            keyStore.getKey(KeyRole.STEP_UP.alias, null) as? PrivateKey
        } catch (error: GeneralSecurityException) {
            throw stepUpLost(error)
        } ?: throw stepUpLost(IllegalStateException("No step-up key in Keystore."))
        return try {
            Signature.getInstance(ReferenceSigningScheme.SIGNATURE_ALGORITHM).apply { initSign(key) }
        } catch (error: KeyPermanentlyInvalidatedException) {
            throw stepUpLost(error)
        } catch (error: ProviderException) {
            throw stepUpLost(error)
        }
    }

    /** Deletes what's left of the step-up key so the next registration starts clean. */
    private fun stepUpLost(cause: Throwable): StepUpKeyInvalidatedException {
        runCatching { delete(KeyRole.STEP_UP) }
        return StepUpKeyInvalidatedException(cause)
    }

    private class KeyPlacement(val strongBox: Boolean, val attested: Boolean)

    private fun generateKeyPair(role: KeyRole, attestationChallenge: ByteArray?, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(role.alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .apply {
                if (attestationChallenge != null) setAttestationChallenge(attestationChallenge)
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setIsStrongBoxBacked(true)
                if (role == KeyRole.STEP_UP) requireAuthenticationPerUse()
            }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
            initialize(spec)
            generateKeyPair()
        }
    }

    /** Every signature needs a fresh authentication; a new fingerprint or removed lock destroys the key. */
    private fun KeyGenParameterSpec.Builder.requireAuthenticationPerUse() {
        setUserAuthenticationRequired(true)
        setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
        } else {
            @Suppress("DEPRECATION")
            setUserAuthenticationValidityDurationSeconds(-1)
        }
    }

    private fun privateKey(role: KeyRole): PrivateKey =
        keyStore.getKey(role.alias, null) as? PrivateKey ?: error("No ${role.name.lowercase()} key in Keystore.")

    private fun protectionOf(key: PrivateKey): SecurityLevel = runCatching {
        val info = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> SecurityLevel.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> SecurityLevel.TRUSTED_ENVIRONMENT
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> SecurityLevel.SOFTWARE
                else -> SecurityLevel.UNKNOWN
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) SecurityLevel.TRUSTED_ENVIRONMENT else SecurityLevel.SOFTWARE
        }
    }.getOrDefault(SecurityLevel.UNKNOWN)

    private val KeyRole.alias: String
        get() = when (this) {
            KeyRole.DEVICE -> "trustgate_device_key"
            KeyRole.STEP_UP -> "trustgate_step_up_key"
        }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}

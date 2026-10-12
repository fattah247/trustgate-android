package id.fatarc.trustgate.ui.payment

import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.GppMaybe
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import id.fatarc.trustgate.core.security.ConfirmationMethod
import java.time.Instant

/**
 * Confirms a medium-risk action. With a screen lock or enrolled biometrics, the system prompt asks
 * the person to prove it's them; without one there's nothing to step up to, so an explicit tap is
 * the honest fallback and the log records which happened.
 */
@Composable
fun StepUpConfirmation(
    requestedAt: Instant?,
    signalNames: List<String>,
    onConfirm: (ConfirmationMethod) -> Unit,
    onDismiss: (problem: String?) -> Unit,
) {
    val activity = LocalContext.current.findFragmentActivity()
    val canStepUp = remember(activity) {
        activity != null &&
            BiometricManager.from(activity).canAuthenticate(StepUpAuthenticators) == BiometricManager.BIOMETRIC_SUCCESS
    }
    val reason = signalSummary(signalNames)

    if (activity != null && canStepUp) {
        val latestConfirm by rememberUpdatedState(onConfirm)
        val latestDismiss by rememberUpdatedState(onDismiss)
        // Built during composition so a recreated activity re-attaches the callback to a prompt still on screen.
        val prompt = remember(activity) {
            BiometricPrompt(
                activity,
                ContextCompat.getMainExecutor(activity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        latestConfirm(ConfirmationMethod.DEVICE_CREDENTIAL)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        // ERROR_CANCELED is the system stopping the prompt (for example the app left the
                        // foreground), not the person choosing to back out, so it carries its message.
                        val userBackedOut = errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                            errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON
                        latestDismiss(if (userBackedOut) null else errString.toString())
                    }
                },
            )
        }
        // If the decision goes away while the system prompt is up, take the prompt down too, except
        // across a configuration change, where the prompt is meant to survive.
        DisposableEffect(prompt) {
            onDispose {
                if (!activity.isChangingConfigurations) prompt.cancelAuthentication()
            }
        }
        // Survives rotation so the same confirmation isn't requested twice.
        var promptedFor by rememberSaveable { mutableStateOf<String?>(null) }
        LaunchedEffect(requestedAt) {
            val key = requestedAt.toString()
            if (promptedFor != key) {
                promptedFor = key
                prompt.authenticate(
                    BiometricPrompt.PromptInfo.Builder()
                        .setTitle("Confirm it's you")
                        .setSubtitle("This device needs review")
                        .setDescription("$reason Confirm to continue the protected action.")
                        .setAllowedAuthenticators(StepUpAuthenticators)
                        .build(),
                )
            }
        }
    } else {
        AlertDialog(
            onDismissRequest = { onDismiss(null) },
            icon = { Icon(Icons.Outlined.GppMaybe, contentDescription = null) },
            title = { Text("Continue on this device?") },
            text = {
                Text(
                    "$reason Continue only if you trust it.\n\nThis device has no screen lock, so TrustGate can't ask " +
                        "you to confirm with a PIN or fingerprint. Your tap is recorded instead.",
                )
            },
            confirmButton = {
                TextButton(onClick = { onConfirm(ConfirmationMethod.TAP) }) { Text("Continue") }
            },
            dismissButton = {
                TextButton(onClick = { onDismiss(null) }) { Text("Cancel") }
            },
        )
    }
}

private fun signalSummary(signalNames: List<String>): String = if (signalNames.isEmpty()) {
    "This device needs review."
} else {
    "Signals found: ${signalNames.take(3).joinToString(", ")}."
}

/** Strong biometrics or the screen lock; before Android 11 the lock can only be paired with weak biometrics everywhere. */
private val StepUpAuthenticators: Int =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) BIOMETRIC_STRONG or DEVICE_CREDENTIAL else BIOMETRIC_WEAK or DEVICE_CREDENTIAL

private tailrec fun Context.findFragmentActivity(): FragmentActivity? = when (this) {
    is FragmentActivity -> this
    is ContextWrapper -> baseContext.findFragmentActivity()
    else -> null
}

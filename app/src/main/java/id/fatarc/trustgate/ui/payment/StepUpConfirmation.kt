package id.fatarc.trustgate.ui.payment

import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
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
import id.fatarc.trustgate.ui.FilterObscuredTouches
import java.security.Signature
import java.time.Instant

/**
 * Confirms a medium-risk action the way the backend asked. With a step-up key, the system prompt
 * unlocks that key's signature: the person's authentication is what lets the request be signed, so
 * skipping or faking the prompt leaves nothing the backend will accept. Without a screen lock there
 * is nothing to step up to, and an explicit tap, signed into the request, is the weaker fallback.
 */
@Composable
fun StepUpConfirmation(
    method: ConfirmationMethod,
    requestedAt: Instant?,
    signalNames: List<String>,
    onRequestSignature: () -> Signature?,
    onAuthenticated: (Signature) -> Unit,
    onConfirmTap: () -> Unit,
    onDismiss: (problem: String?) -> Unit,
) {
    val reason = signalSummary(signalNames)
    val activity = LocalContext.current.findFragmentActivity()

    when {
        method == ConfirmationMethod.TAP -> TapConfirmationDialog(reason, onConfirmTap, onDismiss)
        activity == null -> LaunchedEffect(Unit) { onDismiss("The confirmation prompt couldn't be shown.") }
        else -> CryptoPrompt(activity, requestedAt, reason, onRequestSignature, onAuthenticated, onDismiss)
    }
}

@Composable
private fun CryptoPrompt(
    activity: FragmentActivity,
    requestedAt: Instant?,
    reason: String,
    onRequestSignature: () -> Signature?,
    onAuthenticated: (Signature) -> Unit,
    onDismiss: (problem: String?) -> Unit,
) {
    val latestAuthenticated by rememberUpdatedState(onAuthenticated)
    val latestDismiss by rememberUpdatedState(onDismiss)
    // Built during composition so a recreated activity re-attaches the callback to a prompt still on screen.
    val prompt = remember(activity) {
        BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val unlocked = result.cryptoObject?.signature
                    if (unlocked != null) {
                        latestAuthenticated(unlocked)
                    } else {
                        latestDismiss("The confirmation didn't unlock the signing key.")
                    }
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
        if (promptedFor == key) return@LaunchedEffect
        promptedFor = key
        val signature = onRequestSignature() ?: return@LaunchedEffect
        prompt.authenticate(stepUpPromptInfo(reason), BiometricPrompt.CryptoObject(signature))
    }
}

@Composable
private fun TapConfirmationDialog(
    reason: String,
    onConfirmTap: () -> Unit,
    onDismiss: (problem: String?) -> Unit,
) {
    AlertDialog(
        onDismissRequest = { onDismiss(null) },
        icon = { Icon(Icons.Outlined.GppMaybe, contentDescription = null) },
        title = { Text("Confirm this payment?") },
        text = {
            FilterObscuredTouches()
            Text(reason)
        },
        confirmButton = {
            TextButton(onClick = onConfirmTap) { Text("Pay") }
        },
        dismissButton = {
            TextButton(onClick = { onDismiss(null) }) { Text("Cancel") }
        },
    )
}

/**
 * A key-bound prompt needs strong biometrics. From Android 11 the screen lock can unlock the key
 * too; before that the key only accepts biometrics, so the prompt needs its own cancel button.
 */
private fun stepUpPromptInfo(reason: String): BiometricPrompt.PromptInfo =
    BiometricPrompt.PromptInfo.Builder()
        .setTitle("Confirm this payment")
        .setDescription(reason)
        .apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            } else {
                setAllowedAuthenticators(BIOMETRIC_STRONG)
                setNegativeButtonText("Cancel")
            }
        }
        .build()

private fun signalSummary(signalNames: List<String>): String = if (signalNames.isEmpty()) {
    "The server wants your OK first."
} else {
    "The server wants your OK because it found: ${signalNames.take(2).joinToString(" and ")}."
}

private tailrec fun Context.findFragmentActivity(): FragmentActivity? = when (this) {
    is FragmentActivity -> this
    is ContextWrapper -> baseContext.findFragmentActivity()
    else -> null
}

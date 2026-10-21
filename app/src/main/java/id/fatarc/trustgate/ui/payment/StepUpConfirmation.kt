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
    problems: List<String>,
    scamWarning: Boolean,
    onRequestSignature: () -> Signature?,
    onAuthenticated: (Signature) -> Unit,
    onConfirmTap: () -> Unit,
    onDismiss: (problem: String?) -> Unit,
    title: String = "Confirm this payment",
    confirmLabel: String = "Pay",
    /** Overrides the reason built from [problems], for confirmations that aren't payments. */
    message: String? = null,
) {
    val reason = message ?: confirmationReason(problems, scamWarning)
    val activity = LocalContext.current.findFragmentActivity()

    when {
        method == ConfirmationMethod.TAP -> TapConfirmationDialog(title, confirmLabel, reason, onConfirmTap, onDismiss)
        activity == null -> LaunchedEffect(Unit) { onDismiss("The confirmation prompt couldn't be shown.") }
        else -> CryptoPrompt(activity, requestedAt, title, reason, onRequestSignature, onAuthenticated, onDismiss)
    }
}

@Composable
private fun CryptoPrompt(
    activity: FragmentActivity,
    requestedAt: Instant?,
    title: String,
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
        prompt.authenticate(stepUpPromptInfo(title, reason), BiometricPrompt.CryptoObject(signature))
    }
}

@Composable
private fun TapConfirmationDialog(
    title: String,
    confirmLabel: String,
    reason: String,
    onConfirmTap: () -> Unit,
    onDismiss: (problem: String?) -> Unit,
) {
    AlertDialog(
        onDismissRequest = { onDismiss(null) },
        icon = { Icon(Icons.Outlined.GppMaybe, contentDescription = null) },
        title = { Text("$title?") },
        text = {
            FilterObscuredTouches()
            Text(reason)
        },
        confirmButton = {
            TextButton(onClick = onConfirmTap) { Text(confirmLabel) }
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
private fun stepUpPromptInfo(title: String, reason: String): BiometricPrompt.PromptInfo =
    BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
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

private fun confirmationReason(problems: List<String>, scamWarning: Boolean): String = buildString {
    if (problems.isEmpty()) {
        append("The server wants your OK first.")
    } else {
        append("The server wants your OK because it found: ${problems.take(2).joinToString(" and ")}.")
    }
    if (scamWarning) append(" If someone asked you to pay, stop: it's almost certainly a scam.")
}

private tailrec fun Context.findFragmentActivity(): FragmentActivity? = when (this) {
    is FragmentActivity -> this
    is ContextWrapper -> baseContext.findFragmentActivity()
    else -> null
}

package id.fatarc.trustgate.ui

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.view.View
import android.view.WindowManager
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.platform.LocalView
import id.fatarc.trustgate.BuildConfig
import java.util.WeakHashMap

/**
 * Hardens the window while a sensitive screen is showing. Taps that arrive through another app's
 * overlay are ignored (tapjacking), and release builds block screenshots, screen recording, and
 * the recents thumbnail. Debug builds still allow capture so screens can be documented and tested.
 */
@Composable
fun SensitiveScreen() {
    val view = LocalView.current
    DisposableEffect(view) {
        val activity = view.context.findActivity()
        if (activity != null) SensitiveWindows.acquire(activity, view)
        onDispose {
            if (activity != null) SensitiveWindows.release(activity, view)
        }
    }
}

/**
 * Ignores taps that arrive through another app's overlay in the current window. Dialogs have their
 * own window, so one asking for a confirmation needs this as well as its screen's [SensitiveScreen].
 */
@Composable
fun FilterObscuredTouches() {
    val view = LocalView.current
    DisposableEffect(view) {
        val previous = view.filterTouchesWhenObscured
        view.filterTouchesWhenObscured = true
        onDispose { view.filterTouchesWhenObscured = previous }
    }
}

/**
 * Counts sensitive screens per activity. During a transition between two of them both are on
 * screen for a moment, and the one leaving must not lift protection the arriving one still needs.
 */
private object SensitiveWindows {
    private val holders = WeakHashMap<Activity, Int>()

    fun acquire(activity: Activity, view: View) {
        val count = (holders[activity] ?: 0) + 1
        holders[activity] = count
        if (count == 1) {
            view.filterTouchesWhenObscured = true
            if (BLOCK_CAPTURE) activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    fun release(activity: Activity, view: View) {
        val count = (holders[activity] ?: 1) - 1
        if (count > 0) {
            holders[activity] = count
            return
        }
        holders.remove(activity)
        view.filterTouchesWhenObscured = false
        if (BLOCK_CAPTURE) activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    private val BLOCK_CAPTURE = !BuildConfig.DEBUG
}

private tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}

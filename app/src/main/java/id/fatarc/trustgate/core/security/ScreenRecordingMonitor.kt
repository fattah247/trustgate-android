package id.fatarc.trustgate.core.security

import android.app.Activity
import android.os.Build
import android.view.WindowManager
import androidx.annotation.RequiresApi
import java.util.function.Consumer

/**
 * Whether the app's window is being recorded or shared right now. Android 15 tells an app when its
 * own window is captured; earlier versions don't, and the check reads as not recorded there.
 */
class ScreenRecordingMonitor {
    @Volatile
    var isRecorded: Boolean = false
        private set

    private var watched: Activity? = null
    private val callback: Any? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) recordingCallback() else null

    /** Starts watching [activity]'s window; call from onStart. */
    fun watch(activity: Activity) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM) return
        watched = activity
        addCallback(activity)
    }

    /** Stops watching; call from onStop. */
    fun stop(activity: Activity) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM || watched !== activity) return
        removeCallback(activity)
        watched = null
        isRecorded = false
    }

    @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
    private fun recordingCallback(): Consumer<Int> = Consumer { state ->
        isRecorded = state == WindowManager.SCREEN_RECORDING_STATE_VISIBLE
    }

    @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
    @Suppress("UNCHECKED_CAST")
    private fun addCallback(activity: Activity) {
        val listener = callback as Consumer<Int>
        // The call reports the current state straight away, as well as every change after it.
        isRecorded = activity.windowManager.addScreenRecordingCallback(activity.mainExecutor, listener) ==
            WindowManager.SCREEN_RECORDING_STATE_VISIBLE
    }

    @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
    @Suppress("UNCHECKED_CAST")
    private fun removeCallback(activity: Activity) {
        activity.windowManager.removeScreenRecordingCallback(callback as Consumer<Int>)
    }
}

package id.fatarc.trustgate.ui.events

import android.content.ClipData
import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

private const val EXPORT_DIR = "exports"
private val ExportStamp: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC)

/**
 * Writes the audit log to a private cache file and offers it through the share sheet as a .json
 * attachment. A file keeps the full log out of the intent itself, which has a hard size limit.
 */
internal suspend fun shareAuditLog(context: Context, buildJson: () -> String) {
    val file = withContext(Dispatchers.IO) {
        val dir = File(context.cacheDir, EXPORT_DIR).apply { mkdirs() }
        // Earlier exports were handed off long ago; anything recent may still be uploading somewhere.
        val stale = Instant.now().minus(Duration.ofHours(1)).toEpochMilli()
        dir.listFiles()?.filter { it.lastModified() < stale }?.forEach { it.delete() }
        File(dir, "trustgate-audit-${ExportStamp.format(Instant.now())}.json").apply { writeText(buildJson()) }
    }
    val uri = FileProvider.getUriForFile(context, "${context.packageName}.exports", file)
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "application/json"
        putExtra(Intent.EXTRA_STREAM, uri)
        putExtra(Intent.EXTRA_SUBJECT, "TrustGate audit log")
        clipData = ClipData.newRawUri(file.name, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    context.startActivity(Intent.createChooser(send, "Share audit log"))
}

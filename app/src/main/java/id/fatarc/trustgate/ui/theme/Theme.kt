package id.fatarc.trustgate.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

private val DarkColors = darkColorScheme(
    primary = AppPrimary,
    secondary = AppSecondary,
    tertiary = AppWarning,
    background = AppBackground,
    surface = AppSurface,
    surfaceContainerHigh = AppSurfaceHigh,
    outline = Color(0xFF444048),
    error = AppError,
    errorContainer = AppError.copy(alpha = 0.18f),
    onErrorContainer = AppText,
    onPrimary = AppBackground,
    onSecondary = AppText,
    onBackground = AppText,
    onSurface = AppText,
    onSurfaceVariant = AppTextMuted,
)

private val TrustGateShapes = Shapes(
    extraSmall = RoundedCornerShape(4.dp),
    small = RoundedCornerShape(6.dp),
    medium = RoundedCornerShape(8.dp),
    large = RoundedCornerShape(8.dp),
    extraLarge = RoundedCornerShape(8.dp),
)

@Composable
fun TrustGateTheme(
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = DarkColors,
        typography = TrustGateTypography,
        shapes = TrustGateShapes,
        content = content,
    )
}

package id.fatarc.trustgate.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable

private val LightColors = lightColorScheme(
    primary = Meadow,
    secondary = Moss,
    tertiary = Clay,
    background = Sand,
    surface = Sand,
    onPrimary = Sand,
    onSecondary = Ink,
    onBackground = Ink,
    onSurface = Ink,
)

private val DarkColors = darkColorScheme(
    primary = Moss,
    secondary = Meadow,
    tertiary = Clay,
)

@Composable
fun TrustGateTheme(
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        typography = TrustGateTypography,
        content = content,
    )
}


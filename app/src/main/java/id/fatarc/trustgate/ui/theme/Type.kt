package id.fatarc.trustgate.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight

// The Material 3 type scale on the system font, so text matches the rest of the platform and
// follows the user's font size setting. Only headline weights are nudged for a firmer hierarchy.
private val Base = Typography()

val TrustGateTypography = Base.copy(
    headlineSmall = Base.headlineSmall.copy(fontWeight = FontWeight.Medium),
    headlineMedium = Base.headlineMedium.copy(fontWeight = FontWeight.Medium),
)

val CodeFontFamily = FontFamily.Monospace

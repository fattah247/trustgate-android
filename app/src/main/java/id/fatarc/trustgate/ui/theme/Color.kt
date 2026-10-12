package id.fatarc.trustgate.ui.theme

import androidx.compose.ui.graphics.Color

// Brand: warm paper, ink, and the deep green first set out in res/values/colors.xml.
internal val Paper = Color(0xFFF6F4EF)
internal val Ink = Color(0xFF1F2421)
internal val Pine = Color(0xFF205C4C)

internal object LightPalette {
    val primary = Pine
    val onPrimary = Color(0xFFFFFFFF)
    val primaryContainer = Color(0xFFCBE7DB)
    val onPrimaryContainer = Color(0xFF062A20)
    val inversePrimary = Color(0xFF8FD0B9)

    val secondary = Color(0xFF4E5E57)
    val onSecondary = Color(0xFFFFFFFF)
    val secondaryContainer = Color(0xFFD6E6DE)
    val onSecondaryContainer = Color(0xFF0D2A21)

    val tertiary = Color(0xFF4A5C7A)
    val onTertiary = Color(0xFFFFFFFF)
    val tertiaryContainer = Color(0xFFDCE3F2)
    val onTertiaryContainer = Color(0xFF15233A)

    val error = Color(0xFFA8321F)
    val onError = Color(0xFFFFFFFF)
    val errorContainer = Color(0xFFFADCD4)
    val onErrorContainer = Color(0xFF45120A)

    val caution = Color(0xFF8A5300)
    val cautionContainer = Color(0xFFF8E6C8)
    val onCautionContainer = Color(0xFF3D2500)

    val background = Paper
    val onBackground = Ink
    val surface = Paper
    val onSurface = Ink
    val surfaceVariant = Color(0xFFDFE3DF)
    val onSurfaceVariant = Color(0xFF545B57)
    val surfaceDim = Color(0xFFD8D6D0)
    val surfaceBright = Paper
    val surfaceContainerLowest = Color(0xFFFFFFFF)
    val surfaceContainerLow = Color(0xFFF1EFE9)
    val surfaceContainer = Color(0xFFEBE9E3)
    val surfaceContainerHigh = Color(0xFFE5E3DD)
    val surfaceContainerHighest = Color(0xFFDFDDD7)
    val inverseSurface = Color(0xFF2E3330)
    val inverseOnSurface = Color(0xFFEEF0EC)
    val outline = Color(0xFF7A817D)
    val outlineVariant = Color(0xFFD3D6D1)
}

internal object DarkPalette {
    val primary = Color(0xFF8FD0B9)
    val onPrimary = Color(0xFF00382B)
    val primaryContainer = Color(0xFF1F4F41)
    val onPrimaryContainer = Color(0xFFABEDD4)
    val inversePrimary = Pine

    val secondary = Color(0xFFB6C9C0)
    val onSecondary = Color(0xFF21352E)
    val secondaryContainer = Color(0xFF2E463D)
    val onSecondaryContainer = Color(0xFFD2E5DC)

    val tertiary = Color(0xFFB3C5E6)
    val onTertiary = Color(0xFF1C2D47)
    val tertiaryContainer = Color(0xFF33445F)
    val onTertiaryContainer = Color(0xFFD7E3FA)

    val error = Color(0xFFF2B1A3)
    val onError = Color(0xFF5C1709)
    val errorContainer = Color(0xFF522219)
    val onErrorContainer = Color(0xFFFFDAD2)

    val caution = Color(0xFFE8B866)
    val cautionContainer = Color(0xFF4A3306)
    val onCautionContainer = Color(0xFFFFDDA6)

    val background = Color(0xFF111413)
    val onBackground = Color(0xFFE2E3DF)
    val surface = Color(0xFF111413)
    val onSurface = Color(0xFFE2E3DF)
    val surfaceVariant = Color(0xFF3F4945)
    val onSurfaceVariant = Color(0xFFBFC6C1)
    val surfaceDim = Color(0xFF111413)
    val surfaceBright = Color(0xFF373A39)
    val surfaceContainerLowest = Color(0xFF0C0F0E)
    val surfaceContainerLow = Color(0xFF191C1B)
    val surfaceContainer = Color(0xFF1D201F)
    val surfaceContainerHigh = Color(0xFF272B29)
    val surfaceContainerHighest = Color(0xFF323634)
    val inverseSurface = Color(0xFFE2E3DF)
    val inverseOnSurface = Color(0xFF2E3330)
    val outline = Color(0xFF89918C)
    val outlineVariant = Color(0xFF3A403D)
}

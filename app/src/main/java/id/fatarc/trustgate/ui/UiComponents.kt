package id.fatarc.trustgate.ui

import android.os.Build
import android.text.format.DateFormat
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MediumTopAppBar
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.layout.layout
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.max
import androidx.compose.ui.unit.sp
import androidx.core.os.ConfigurationCompat
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.DeviceRiskReport
import id.fatarc.trustgate.domain.risk.RiskSignal
import id.fatarc.trustgate.domain.risk.SignalSeverity
import id.fatarc.trustgate.ui.theme.CodeFontFamily
import id.fatarc.trustgate.ui.theme.TrustGateTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.math.BigDecimal
import java.text.NumberFormat
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Currency
import java.util.Locale

object TrustGateSpacing {
    val screenHorizontal = 16.dp
    val sectionGap = 24.dp
    val maxContentWidth = 640.dp
    val listIconInset = 56.dp
}

val LocalSnackbarHostState = staticCompositionLocalOf { SnackbarHostState() }

/** Horizontal margin of the current screen's list, for rows that scroll edge to edge. */
val LocalScreenGutter = compositionLocalOf { TrustGateSpacing.screenHorizontal }

val CodeTextStyle: TextStyle
    @Composable
    @ReadOnlyComposable
    get() = MaterialTheme.typography.bodyMedium.copy(
        fontFamily = CodeFontFamily,
        fontSize = 13.sp,
        lineHeight = 20.sp,
    )

// region Tone

/** Colour is reserved for state. Neutral content stays in the surface colours. */
enum class Tone {
    NEUTRAL,
    POSITIVE,
    CAUTION,
    CRITICAL,
}

@Composable
@ReadOnlyComposable
fun Tone.contentColor(): Color = when (this) {
    Tone.NEUTRAL -> MaterialTheme.colorScheme.onSurfaceVariant
    Tone.POSITIVE -> MaterialTheme.colorScheme.primary
    Tone.CAUTION -> TrustGateTheme.colors.caution
    Tone.CRITICAL -> MaterialTheme.colorScheme.error
}

@Composable
@ReadOnlyComposable
fun Tone.containerColor(): Color = when (this) {
    Tone.NEUTRAL -> MaterialTheme.colorScheme.surfaceContainerHigh
    Tone.POSITIVE -> MaterialTheme.colorScheme.primaryContainer
    Tone.CAUTION -> TrustGateTheme.colors.cautionContainer
    Tone.CRITICAL -> MaterialTheme.colorScheme.errorContainer
}

@Composable
@ReadOnlyComposable
fun Tone.onContainerColor(): Color = when (this) {
    Tone.NEUTRAL -> MaterialTheme.colorScheme.onSurface
    Tone.POSITIVE -> MaterialTheme.colorScheme.onPrimaryContainer
    Tone.CAUTION -> TrustGateTheme.colors.onCautionContainer
    Tone.CRITICAL -> MaterialTheme.colorScheme.onErrorContainer
}

// endregion

// region Risk vocabulary

fun DeviceRiskLevel.label(): String = when (this) {
    DeviceRiskLevel.LOW -> "Low risk"
    DeviceRiskLevel.MEDIUM -> "Medium risk"
    DeviceRiskLevel.HIGH -> "High risk"
}

fun DeviceRiskLevel.tone(): Tone = when (this) {
    DeviceRiskLevel.LOW -> Tone.POSITIVE
    DeviceRiskLevel.MEDIUM -> Tone.CAUTION
    DeviceRiskLevel.HIGH -> Tone.CRITICAL
}

fun SignalSeverity.label(): String = when (this) {
    SignalSeverity.LOW -> "Low"
    SignalSeverity.MEDIUM -> "Medium"
    SignalSeverity.HIGH -> "High"
}

fun SignalSeverity.tone(): Tone = when (this) {
    SignalSeverity.LOW -> Tone.NEUTRAL
    SignalSeverity.MEDIUM -> Tone.CAUTION
    SignalSeverity.HIGH -> Tone.CRITICAL
}

/** The reference payment as people read amounts, for example "IDR 1,250.00" or "Rp 1.250,00". */
fun formatMinorAmount(amountMinor: Long, currencyCode: String, locale: Locale): String {
    val currency = Currency.getInstance(currencyCode)
    val format = NumberFormat.getCurrencyInstance(locale).apply { this.currency = currency }
    return format.format(BigDecimal.valueOf(amountMinor, currency.defaultFractionDigits.coerceAtLeast(0)))
}

/** Detected signals, strongest first. */
fun DeviceRiskReport.flaggedSignals(): List<RiskSignal> = signals
    .filter { it.detected }
    .sortedWith(
        compareByDescending<RiskSignal> { it.severity.weight }
            .thenBy { it.category.ordinal }
            .thenBy { it.name },
    )

// endregion

// region Screen structure

/**
 * Shared screen frame. Top-level screens get a medium app bar that collapses as the list scrolls;
 * pushed screens get a small bar with an up button.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScreenScaffold(
    title: String,
    modifier: Modifier = Modifier,
    onNavigateUp: (() -> Unit)? = null,
    actions: @Composable RowScope.() -> Unit = {},
    itemSpacing: Dp = TrustGateSpacing.sectionGap,
    listState: LazyListState = rememberLazyListState(),
    content: LazyListScope.() -> Unit,
) {
    val scrollBehavior = if (onNavigateUp == null) {
        TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
    } else {
        TopAppBarDefaults.pinnedScrollBehavior()
    }
    Scaffold(
        modifier = modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            if (onNavigateUp == null) {
                MediumTopAppBar(
                    title = { Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    actions = actions,
                    scrollBehavior = scrollBehavior,
                )
            } else {
                TopAppBar(
                    title = { Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    navigationIcon = {
                        IconButton(onClick = onNavigateUp) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Navigate up")
                        }
                    },
                    actions = actions,
                    scrollBehavior = scrollBehavior,
                )
            }
        },
    ) { innerPadding ->
        BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
            // Keep line length readable on tablets and in landscape.
            val gutter = max(
                TrustGateSpacing.screenHorizontal,
                (maxWidth - TrustGateSpacing.maxContentWidth) / 2,
            )
            val layoutDirection = LocalLayoutDirection.current
            CompositionLocalProvider(LocalScreenGutter provides gutter) {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(
                        start = innerPadding.calculateStartPadding(layoutDirection) + gutter,
                        top = innerPadding.calculateTopPadding() + 8.dp,
                        end = innerPadding.calculateEndPadding(layoutDirection) + gutter,
                        bottom = innerPadding.calculateBottomPadding() + 32.dp,
                    ),
                    verticalArrangement = Arrangement.spacedBy(itemSpacing),
                    content = content,
                )
            }
        }
    }
}

/** Lets a horizontally scrolling row run under the screen margins while its content stays aligned. */
@Composable
fun Modifier.bleedToScreenEdges(): Modifier {
    val gutter = LocalScreenGutter.current
    return this
        .layout { measurable, constraints ->
            val extra = (gutter * 2).roundToPx()
            val width = constraints.maxWidth + extra
            val placeable = measurable.measure(constraints.copy(minWidth = width, maxWidth = width))
            layout(constraints.maxWidth, placeable.height) {
                placeable.placeRelative(-extra / 2, 0)
            }
        }
}

@Composable
fun SectionHeader(
    title: String,
    modifier: Modifier = Modifier,
    action: (@Composable () -> Unit)? = null,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = 40.dp)
            .padding(start = 16.dp, end = if (action != null) 4.dp else 16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = title,
            modifier = Modifier
                .weight(1f)
                .semantics { heading() },
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        action?.invoke()
    }
}

@Composable
fun SectionFooter(
    text: String,
    modifier: Modifier = Modifier,
) {
    Text(
        text = text,
        modifier = modifier.padding(start = 16.dp, top = 8.dp, end = 16.dp),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

/** A titled group of rows on one rounded surface, like a settings list. */
@Composable
fun Section(
    modifier: Modifier = Modifier,
    title: String? = null,
    action: (@Composable () -> Unit)? = null,
    footer: String? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(modifier = modifier.fillMaxWidth()) {
        if (title != null) {
            SectionHeader(title = title, action = action)
            Spacer(Modifier.height(4.dp))
        }
        GroupedSurface(content = content)
        if (footer != null) {
            SectionFooter(text = footer)
        }
    }
}

@Composable
fun GroupedSurface(
    modifier: Modifier = Modifier,
    shape: Shape = MaterialTheme.shapes.medium,
    content: @Composable ColumnScope.() -> Unit,
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = shape,
        color = TrustGateTheme.colors.groupedSurface,
        contentColor = MaterialTheme.colorScheme.onSurface,
    ) {
        Column(content = content)
    }
}

/** Where a row sits inside a group that is split across lazy list items. */
enum class GroupPosition {
    FIRST,
    MIDDLE,
    LAST,
    ONLY,
    ;

    val isLast: Boolean get() = this == LAST || this == ONLY

    companion object {
        fun of(index: Int, count: Int): GroupPosition = when {
            count == 1 -> ONLY
            index == 0 -> FIRST
            index == count - 1 -> LAST
            else -> MIDDLE
        }
    }
}

@Composable
@ReadOnlyComposable
fun GroupPosition.shape(): Shape {
    val corner = GroupCorner
    return when (this) {
        GroupPosition.ONLY -> MaterialTheme.shapes.medium
        GroupPosition.FIRST -> RoundedCornerShape(topStart = corner, topEnd = corner)
        GroupPosition.LAST -> RoundedCornerShape(bottomStart = corner, bottomEnd = corner)
        GroupPosition.MIDDLE -> RectangleShape
    }
}

private val GroupCorner = 16.dp

@Composable
fun RowDivider(startIndent: Dp = 16.dp) {
    HorizontalDivider(
        modifier = Modifier.padding(start = startIndent),
        color = MaterialTheme.colorScheme.outlineVariant,
    )
}

// endregion

// region Rows

@Composable
fun ListRow(
    headline: String,
    modifier: Modifier = Modifier,
    supporting: String? = null,
    supportingColor: Color = Color.Unspecified,
    supportingMaxLines: Int = Int.MAX_VALUE,
    leadingIcon: ImageVector? = null,
    leadingTint: Color = Color.Unspecified,
    leadingIconDescription: String? = null,
    trailing: (@Composable () -> Unit)? = null,
    onClickLabel: String? = null,
    onClick: (() -> Unit)? = null,
) {
    ListItem(
        modifier = if (onClick != null) {
            modifier.clickable(onClickLabel = onClickLabel, onClick = onClick)
        } else {
            modifier
        },
        headlineContent = { Text(headline) },
        supportingContent = supporting?.let { text ->
            {
                Text(
                    text = text,
                    color = supportingColor,
                    maxLines = supportingMaxLines,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        },
        leadingContent = leadingIcon?.let { icon ->
            {
                Icon(
                    imageVector = icon,
                    contentDescription = leadingIconDescription,
                    tint = if (leadingTint == Color.Unspecified) {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    } else {
                        leadingTint
                    },
                )
            }
        },
        trailingContent = trailing,
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
    )
}

/** Label above a value that may be long, such as a hash or header. */
@Composable
fun ValueRow(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    monospace: Boolean = false,
    copyable: Boolean = false,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(start = 16.dp, top = 12.dp, end = if (copyable) 4.dp else 16.dp, bottom = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier
                .weight(1f)
                .semantics(mergeDescendants = true) {},
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = value,
                style = if (monospace) CodeTextStyle else MaterialTheme.typography.bodyLarge,
            )
        }
        if (copyable) {
            CopyButton(label = label, value = value)
        }
    }
}

@Composable
fun CopyButton(
    label: String,
    value: String,
) {
    val clipboard = LocalClipboardManager.current
    val snackbarHostState = LocalSnackbarHostState.current
    val scope = rememberCoroutineScope()
    var copied by remember { mutableStateOf(false) }
    LaunchedEffect(copied) {
        if (copied) {
            delay(1_500)
            copied = false
        }
    }
    IconButton(
        onClick = {
            clipboard.setText(AnnotatedString(value))
            copied = true
            // Android 13 and later confirm clipboard writes with their own overlay.
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                scope.launch { snackbarHostState.showSnackbar("$label copied") }
            }
        },
    ) {
        // The icon itself confirms the copy, so the button answers the tap right where it happened.
        AnimatedContent(
            targetState = copied,
            transitionSpec = {
                (scaleIn(initialScale = 0.6f) + fadeIn()) togetherWith (scaleOut(targetScale = 0.6f) + fadeOut())
            },
            label = "copyFeedback",
        ) { isCopied ->
            Icon(
                imageVector = if (isCopied) Icons.Outlined.Check else Icons.Outlined.ContentCopy,
                contentDescription = if (isCopied) "$label copied" else "Copy $label",
                tint = if (isCopied) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
fun SwitchRow(
    title: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
    supporting: String? = null,
) {
    ListItem(
        modifier = modifier.toggleable(
            value = checked,
            role = Role.Switch,
            onValueChange = onCheckedChange,
        ),
        headlineContent = { Text(title) },
        supportingContent = supporting?.let { text -> { Text(text) } },
        trailingContent = { Switch(checked = checked, onCheckedChange = null) },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
    )
}

@Composable
fun BulletItem(
    text: String,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 6.dp),
    ) {
        Text(
            text = "•",
            modifier = Modifier.width(16.dp),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = text,
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodyLarge,
        )
    }
}

// endregion

// region Formatting

/** Dates and times in the person's locale, honouring the system 12/24-hour setting. */
class TimeFormats(
    locale: Locale,
    is24Hour: Boolean,
    private val zone: ZoneId,
    private val today: LocalDate,
) {
    private val time = formatter(locale, if (is24Hour) "Hm" else "hm")
    private val preciseTime = formatter(locale, if (is24Hour) "Hms" else "hms")
    private val dayThisYear = formatter(locale, "EEEdMMM")
    private val dayOtherYear = formatter(locale, "EEEdMMMy")
    private val shortDay = formatter(locale, "dMMM")

    fun localDate(instant: Instant): LocalDate = instant.atZone(zone).toLocalDate()

    fun time(instant: Instant): String = instant.atZone(zone).format(time)

    fun preciseTime(instant: Instant): String = instant.atZone(zone).format(preciseTime)

    fun day(date: LocalDate): String = when {
        date == today -> "Today"
        date == today.minusDays(1) -> "Yesterday"
        date.year == today.year -> date.format(dayThisYear)
        else -> date.format(dayOtherYear)
    }

    fun dayAndTime(instant: Instant): String = "${day(localDate(instant))}, ${time(instant)}"

    /** Time for today's entries, otherwise a short date. Fits a trailing list slot. */
    fun compact(instant: Instant): String {
        val date = localDate(instant)
        return if (date == today) time(instant) else date.format(shortDay)
    }

    private fun formatter(locale: Locale, skeleton: String): DateTimeFormatter =
        DateTimeFormatter.ofPattern(DateFormat.getBestDateTimePattern(locale, skeleton), locale)
}

@Composable
fun rememberTimeFormats(): TimeFormats {
    val context = LocalContext.current
    val configuration = LocalConfiguration.current
    val locale = ConfigurationCompat.getLocales(configuration)[0] ?: Locale.getDefault()
    val is24Hour = DateFormat.is24HourFormat(context)
    val today = LocalDate.now()
    return remember(locale, is24Hour, today) {
        TimeFormats(
            locale = locale,
            is24Hour = is24Hour,
            zone = ZoneId.systemDefault(),
            today = today,
        )
    }
}

fun parseInstantOrNull(raw: String): Instant? = runCatching { Instant.parse(raw) }.getOrNull()

fun maskToken(token: String): String {
    if (token.length <= 10) return "•".repeat(8)
    return token.take(6) + "•".repeat(6) + token.takeLast(4)
}

// endregion

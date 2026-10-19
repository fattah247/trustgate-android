package id.fatarc.trustgate.ui.events

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.DeleteSweep
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.domain.events.SECURITY_EVENT_LIMIT
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.ui.CodeTextStyle
import id.fatarc.trustgate.ui.GateMark
import id.fatarc.trustgate.ui.GateState
import id.fatarc.trustgate.ui.GroupPosition
import id.fatarc.trustgate.ui.ListRow
import id.fatarc.trustgate.ui.LocalScreenGutter
import id.fatarc.trustgate.ui.RowDivider
import id.fatarc.trustgate.ui.ScreenScaffold
import id.fatarc.trustgate.ui.SectionFooter
import id.fatarc.trustgate.ui.SectionHeader
import id.fatarc.trustgate.ui.TimeFormats
import id.fatarc.trustgate.ui.Tone
import id.fatarc.trustgate.ui.TrustGateSpacing
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.bleedToScreenEdges
import id.fatarc.trustgate.ui.contentColor
import id.fatarc.trustgate.ui.label
import id.fatarc.trustgate.ui.parseInstantOrNull
import id.fatarc.trustgate.ui.rememberTimeFormats
import id.fatarc.trustgate.ui.shape
import id.fatarc.trustgate.ui.theme.TrustGateTheme
import kotlinx.coroutines.launch

@Composable
fun SecurityEventLogScreen(
    uiState: TrustGateUiState,
    onClearEvents: () -> Unit,
    onExportEvents: () -> String,
    onCheckDevice: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val formats = rememberTimeFormats()
    var filter by rememberSaveable { mutableStateOf(EventFilter.ALL) }
    var expandedIds by rememberSaveable { mutableStateOf(emptySet<String>()) }
    var confirmClear by rememberSaveable { mutableStateOf(false) }

    val allEvents = uiState.securityEvents
    val days = remember(allEvents, filter, formats) {
        allEvents
            .asReversed()
            .filter { it.matches(filter) }
            .groupBy { event -> parseInstantOrNull(event.timestamp)?.let(formats::localDate) }
    }

    ScreenScaffold(
        title = "Activity",
        actions = {
            IconButton(
                onClick = { scope.launch { shareAuditLog(context, onExportEvents) } },
                enabled = allEvents.isNotEmpty(),
            ) {
                Icon(Icons.Outlined.Share, contentDescription = "Share the log")
            }
            IconButton(onClick = { confirmClear = true }, enabled = allEvents.isNotEmpty()) {
                Icon(Icons.Outlined.DeleteSweep, contentDescription = "Clear activity")
            }
        },
        itemSpacing = 0.dp,
    ) {
        item(key = "filters") {
            FilterRow(
                selected = filter,
                onSelect = { filter = it },
                modifier = Modifier.padding(bottom = 16.dp),
            )
        }

        if (days.isEmpty()) {
            item(key = "empty") {
                EmptyLog(
                    filtered = filter != EventFilter.ALL,
                    filterLabel = filter.label,
                    onCheckDevice = onCheckDevice,
                    onShowAll = { filter = EventFilter.ALL },
                )
            }
        }

        days.forEach { (date, dayEvents) ->
            item(key = "day-$date") {
                SectionHeader(
                    title = date?.let(formats::day) ?: "Unknown date",
                    modifier = Modifier
                        .animateItem()
                        .padding(bottom = 4.dp),
                )
            }
            itemsIndexed(dayEvents, key = { _, event -> event.id }) { index, event ->
                val expanded = event.id in expandedIds
                EventRow(
                    event = event,
                    position = GroupPosition.of(index, dayEvents.size),
                    expanded = expanded,
                    formats = formats,
                    onToggle = {
                        expandedIds = if (expanded) expandedIds - event.id else expandedIds + event.id
                    },
                    modifier = Modifier.animateItem(),
                )
            }
            item(key = "gap-$date") {
                Spacer(Modifier.height(TrustGateSpacing.sectionGap))
            }
        }

        if (allEvents.isNotEmpty()) {
            item(key = "footer") {
                SectionFooter(text = "Keeps the latest $SECURITY_EVENT_LIMIT events, on this phone only.")
            }
        }
    }

    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            icon = { Icon(Icons.Outlined.DeleteSweep, contentDescription = null) },
            title = { Text("Clear activity?") },
            text = {
                Text(
                    "All ${allEvents.size} events will be deleted. This can't be undone.",
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmClear = false
                        expandedIds = emptySet()
                        onClearEvents()
                    },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                ) {
                    Text("Clear")
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmClear = false }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun EmptyLog(
    filtered: Boolean,
    filterLabel: String,
    onCheckDevice: () -> Unit,
    onShowAll: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 24.dp, vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        GateMark(state = GateState.SHUT, tone = Tone.NEUTRAL, contentDescription = null, size = 88.dp)
        Spacer(Modifier.height(8.dp))
        Text(
            text = if (filtered) "No ${filterLabel.lowercase()} activity yet" else "Nothing here yet",
            style = MaterialTheme.typography.titleMedium,
            textAlign = TextAlign.Center,
        )
        Text(
            text = if (filtered) {
                "Try a payment or a Lab test."
            } else {
                "Checks and payments show up here."
            },
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(4.dp))
        if (filtered) {
            TextButton(onClick = onShowAll) { Text("Show all activity") }
        } else {
            FilledTonalButton(onClick = onCheckDevice) { Text("Check this phone") }
        }
    }
}

@Composable
private fun FilterRow(
    selected: EventFilter,
    onSelect: (EventFilter) -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .bleedToScreenEdges()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = LocalScreenGutter.current),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        EventFilter.entries.forEach { option ->
            val isSelected = option == selected
            FilterChip(
                selected = isSelected,
                onClick = { onSelect(option) },
                label = { Text(option.label) },
                leadingIcon = if (isSelected) {
                    {
                        Icon(
                            imageVector = Icons.Outlined.Check,
                            contentDescription = null,
                            modifier = Modifier.size(FilterChipDefaults.IconSize),
                        )
                    }
                } else {
                    null
                },
            )
        }
    }
}

@Composable
private fun EventRow(
    event: SecurityEvent,
    position: GroupPosition,
    expanded: Boolean,
    formats: TimeFormats,
    onToggle: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val instant = parseInstantOrNull(event.timestamp)
    val chevronRotation by animateFloatAsState(targetValue = if (expanded) 180f else 0f, label = "chevron")

    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = position.shape(),
        color = TrustGateTheme.colors.groupedSurface,
        contentColor = MaterialTheme.colorScheme.onSurface,
    ) {
        Column {
            ListRow(
                headline = event.headline(),
                supporting = event.message,
                supportingColor = MaterialTheme.colorScheme.onSurfaceVariant,
                supportingMaxLines = if (expanded) Int.MAX_VALUE else 2,
                leadingIcon = event.icon,
                leadingTint = event.tone().contentColor(),
                trailing = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (instant != null) {
                            Text(
                                text = formats.time(instant),
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Icon(
                            imageVector = Icons.Outlined.ExpandMore,
                            contentDescription = null,
                            modifier = Modifier
                                .size(20.dp)
                                .rotate(chevronRotation),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
                onClickLabel = if (expanded) "Hide details" else "Show details",
                onClick = onToggle,
                modifier = Modifier.semantics {
                    stateDescription = if (expanded) "Expanded" else "Collapsed"
                },
            )
            AnimatedVisibility(
                visible = expanded,
                enter = expandVertically() + fadeIn(),
                exit = shrinkVertically() + fadeOut(),
            ) {
                Column(
                    modifier = Modifier.padding(
                        start = TrustGateSpacing.listIconInset,
                        end = 16.dp,
                        bottom = 12.dp,
                    ),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    if (instant != null) {
                        DetailLine(
                            label = "When",
                            value = "${formats.day(formats.localDate(instant))}, ${formats.preciseTime(instant)}",
                        )
                    }
                    event.riskLevel?.let { level ->
                        DetailLine(label = "Risk", value = level.label())
                    }
                    event.metadata.toSortedMap().forEach { (key, value) ->
                        DetailLine(
                            label = metadataLabel(key),
                            value = metadataValue(key, value),
                            monospace = key in MonospaceMetadata,
                        )
                    }
                }
            }
            if (!position.isLast) {
                RowDivider(startIndent = TrustGateSpacing.listIconInset)
            }
        }
    }
}

@Composable
private fun DetailLine(
    label: String,
    value: String,
    monospace: Boolean = false,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = label,
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            modifier = Modifier.weight(1.4f),
            style = if (monospace) CodeTextStyle else MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.End,
        )
    }
}

private val MonospaceMetadata = setOf("nonce", "signaturePrefix", "signalId", "keyId", "idempotencyKey", "paymentId")

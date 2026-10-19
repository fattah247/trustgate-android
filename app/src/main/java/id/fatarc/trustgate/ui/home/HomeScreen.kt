package id.fatarc.trustgate.ui.home

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Storefront
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.os.ConfigurationCompat
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.ReferencePayment
import id.fatarc.trustgate.ui.DemoPhone
import id.fatarc.trustgate.ui.DemoPhoneButton
import id.fatarc.trustgate.ui.DemoPhoneSheet
import id.fatarc.trustgate.ui.ListRow
import id.fatarc.trustgate.ui.RowDivider
import id.fatarc.trustgate.ui.ScreenScaffold
import id.fatarc.trustgate.ui.Section
import id.fatarc.trustgate.ui.StatusHero
import id.fatarc.trustgate.ui.TimeFormats
import id.fatarc.trustgate.ui.TrustGateSpacing
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.contentColor
import id.fatarc.trustgate.ui.events.headline
import id.fatarc.trustgate.ui.events.icon
import id.fatarc.trustgate.ui.events.isDetail
import id.fatarc.trustgate.ui.events.tone
import id.fatarc.trustgate.ui.flaggedSignals
import id.fatarc.trustgate.ui.formatMinorAmount
import id.fatarc.trustgate.ui.parseInstantOrNull
import id.fatarc.trustgate.ui.phoneStatus
import id.fatarc.trustgate.ui.rememberTimeFormats
import id.fatarc.trustgate.ui.theme.TrustGateTheme
import java.util.Locale

@Composable
fun HomeScreen(
    uiState: TrustGateUiState,
    onRefreshRisk: () -> Unit,
    onPay: () -> Unit,
    onSelectDemoPhone: (DeviceRiskLevel?) -> Unit,
    onOpenActivity: () -> Unit,
    onOpenAbout: () -> Unit,
) {
    val formats = rememberTimeFormats()
    val risk = uiState.risk
    val status = risk.phoneStatus()
    val demoPhone = DemoPhone.of(risk.scenarioLevel)
    var choosingPhone by rememberSaveable { mutableStateOf(false) }
    val recentEvents = uiState.securityEvents.asReversed().asSequence().filterNot { it.isDetail }.take(3).toList()

    ScreenScaffold(
        title = "TrustGate",
        actions = {
            IconButton(onClick = onOpenAbout) {
                Icon(Icons.Outlined.Info, contentDescription = "About TrustGate")
            }
        },
    ) {
        item(key = "demo") {
            DemoPhoneButton(selected = demoPhone, onClick = { choosingPhone = true })
        }

        item(key = "status") {
            StatusHero(
                status = status,
                findings = risk.report?.flaggedSignals().orEmpty().map { it.name }.shortened(),
                footer = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = when {
                                risk.isLoading -> "Checking…"
                                risk.report != null && risk.errorMessage != null -> "Last check didn't finish"
                                else -> risk.report?.let { "Checked ${formats.time(it.assessedAt)}" }.orEmpty()
                            },
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        TextButton(onClick = onRefreshRisk, enabled = !risk.isLoading) { Text("Check again") }
                    }
                },
            )
        }

        item(key = "pay") {
            CheckoutCard(onPay = onPay, enabled = risk.report != null && !uiState.payment.isRunning)
        }

        item(key = "recent") {
            Section(
                title = "Recent",
                action = if (uiState.securityEvents.isNotEmpty()) {
                    { TextButton(onClick = onOpenActivity) { Text("See all") } }
                } else {
                    null
                },
            ) {
                if (recentEvents.isEmpty()) {
                    ListRow(headline = "Nothing yet", supporting = "Your checks and payments will show here.")
                } else {
                    recentEvents.forEachIndexed { index, event ->
                        RecentRow(event = event, formats = formats)
                        if (index != recentEvents.lastIndex) RowDivider(startIndent = TrustGateSpacing.listIconInset)
                    }
                }
            }
        }
    }

    if (choosingPhone) {
        DemoPhoneSheet(
            selected = demoPhone,
            onSelect = { phone ->
                choosingPhone = false
                onSelectDemoPhone(phone.level)
            },
            onDismiss = { choosingPhone = false },
        )
    }
}

/** The test purchase: who it's to, how much, and the one button that starts it. */
@Composable
private fun CheckoutCard(
    onPay: () -> Unit,
    enabled: Boolean,
) {
    val locale = ConfigurationCompat.getLocales(LocalConfiguration.current)[0] ?: Locale.getDefault()
    val amount = formatMinorAmount(ReferencePayment.AMOUNT_MINOR, ReferencePayment.CURRENCY, locale)
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(28.dp),
        color = TrustGateTheme.colors.groupedSurface,
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                MerchantBadge()
                Column(modifier = Modifier.weight(1f)) {
                    Text("TrustGate Store", style = MaterialTheme.typography.titleMedium)
                    Text("Test payment", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            Spacer(Modifier.height(16.dp))
            Text(amount, style = MaterialTheme.typography.displaySmall, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(16.dp))
            Button(
                onClick = onPay,
                enabled = enabled,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 56.dp),
            ) {
                Text("Pay $amount", style = MaterialTheme.typography.titleMedium)
            }
        }
    }
}

@Composable
fun MerchantBadge(modifier: Modifier = Modifier) {
    Surface(modifier = modifier.size(44.dp), shape = CircleShape, color = MaterialTheme.colorScheme.secondaryContainer) {
        Box(contentAlignment = Alignment.Center) {
            Icon(Icons.Outlined.Storefront, contentDescription = null, tint = MaterialTheme.colorScheme.onSecondaryContainer)
        }
    }
}

@Composable
private fun RecentRow(
    event: SecurityEvent,
    formats: TimeFormats,
) {
    ListRow(
        headline = event.headline(),
        leadingIcon = event.icon,
        leadingTint = event.tone().contentColor(),
        trailing = {
            parseInstantOrNull(event.timestamp)?.let { instant ->
                Text(formats.compact(instant), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        },
    )
}

/** At most three names, then a count, so the chips stay on two lines. */
private fun List<String>.shortened(): List<String> = if (size <= 3) this else take(2) + "+${size - 2} more"

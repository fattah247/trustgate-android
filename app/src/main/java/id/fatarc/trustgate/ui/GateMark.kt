package id.fatarc.trustgate.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel

/** The product's mark: a garden gate whose doors say what the gate will do. */
enum class GateState(internal val openFraction: Float) {
    OPEN(1f),
    AJAR(0.42f),
    SHUT(0f),
    LOCKED(0f),

    /** Shut while the lamp pulses, for a check that hasn't finished yet. */
    CHECKING(0f),
}

fun DeviceRiskLevel.gateState(): GateState = when (this) {
    DeviceRiskLevel.LOW -> GateState.OPEN
    DeviceRiskLevel.MEDIUM -> GateState.AJAR
    DeviceRiskLevel.HIGH -> GateState.LOCKED
}

/**
 * Draws the gate in a 100 × 100 design space scaled to [size]. Changes spring between states so a
 * verdict reads as the gate opening or closing; the system animation scale turns the motion off.
 */
@Composable
fun GateMark(
    state: GateState,
    tone: Tone,
    contentDescription: String?,
    modifier: Modifier = Modifier,
    size: Dp = 56.dp,
) {
    val openFraction by animateFloatAsState(
        targetValue = state.openFraction,
        animationSpec = spring(dampingRatio = 0.55f, stiffness = Spring.StiffnessLow),
        label = "gateOpen",
    )
    val lockScale by animateFloatAsState(
        targetValue = if (state == GateState.LOCKED) 1f else 0f,
        animationSpec = spring(dampingRatio = 0.45f, stiffness = Spring.StiffnessMediumLow),
        label = "gateLock",
    )
    val structure by animateColorAsState(tone.contentColor(), label = "gateStructure")
    val panel by animateColorAsState(tone.containerColor(), label = "gatePanel")
    val ground = MaterialTheme.colorScheme.outlineVariant
    val lampAlpha = if (state == GateState.CHECKING) {
        val pulse = rememberInfiniteTransition(label = "gateLamp")
        pulse.animateFloat(
            initialValue = 0.25f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(tween(durationMillis = 650), RepeatMode.Reverse),
            label = "gateLampAlpha",
        ).value
    } else {
        1f
    }

    Canvas(
        modifier = modifier
            .size(size)
            .semantics {
                if (contentDescription != null) {
                    this.contentDescription = contentDescription
                    role = Role.Image
                }
            },
    ) {
        val u = this.size.minDimension / 100f
        drawGate(
            u = u,
            openFraction = openFraction,
            lockScale = lockScale,
            lampAlpha = lampAlpha,
            structure = structure,
            panel = panel,
            ground = ground,
        )
    }
}

private fun DrawScope.drawGate(
    u: Float,
    openFraction: Float,
    lockScale: Float,
    lampAlpha: Float,
    structure: Color,
    panel: Color,
    ground: Color,
) {
    fun p(x: Float, y: Float) = Offset(x * u, y * u)

    // A path through the gate shows up as the doors open: the way is clear.
    if (openFraction > 0.05f) {
        val path = Path().apply {
            moveTo(42f * u, 92f * u)
            lineTo(58f * u, 92f * u)
            lineTo(53f * u, 60f * u)
            lineTo(47f * u, 60f * u)
            close()
        }
        drawPath(path, color = panel.copy(alpha = (openFraction * 0.9f).coerceIn(0f, 1f)))
    }
    drawLine(ground, p(4f, 93f), p(96f, 93f), strokeWidth = 3f * u, cap = StrokeCap.Round)

    // Doors hinge on the posts; as they swing towards the viewer they narrow.
    val leafWidth = 26f * (1f - openFraction.coerceIn(0f, 1.2f) * 0.78f)
    drawLeaf(u, hingeX = 24f, width = leafWidth, fromLeft = true, panel = panel, structure = structure)
    drawLeaf(u, hingeX = 76f, width = leafWidth, fromLeft = false, panel = panel, structure = structure)

    // Posts with round finials, joined by an arch.
    val post = CornerRadius(6f * u)
    drawRoundRect(structure, topLeft = p(10f, 30f), size = Size(14f * u, 62f * u), cornerRadius = post)
    drawRoundRect(structure, topLeft = p(76f, 30f), size = Size(14f * u, 62f * u), cornerRadius = post)
    drawCircle(structure, radius = 6.5f * u, center = p(17f, 24f))
    drawCircle(structure, radius = 6.5f * u, center = p(83f, 24f))
    val arch = Path().apply {
        moveTo(17f * u, 36f * u)
        quadraticBezierTo(50f * u, -2f * u, 83f * u, 36f * u)
    }
    drawPath(arch, color = structure, style = Stroke(width = 6f * u, cap = StrokeCap.Round))

    // The lamp hangs from the arch and carries the verdict colour.
    drawLine(structure, p(50f, 16f), p(50f, 22f), strokeWidth = 2.5f * u, cap = StrokeCap.Round)
    drawCircle(structure.copy(alpha = lampAlpha), radius = 5f * u, center = p(50f, 27f))

    if (lockScale > 0.01f) {
        val s = lockScale
        val cx = 50f
        val top = 64f
        drawArc(
            color = structure,
            startAngle = 180f,
            sweepAngle = 180f,
            useCenter = false,
            topLeft = p(cx - 6f * s, top - 6f * s),
            size = Size(12f * s * u, 12f * s * u),
            style = Stroke(width = 3f * u * s, cap = StrokeCap.Round),
        )
        drawRoundRect(
            color = structure,
            topLeft = p(cx - 9f * s, top),
            size = Size(18f * s * u, 14f * s * u),
            cornerRadius = CornerRadius(3f * u * s),
        )
        drawCircle(panel, radius = 2.2f * u * s, center = p(cx, top + 6.5f * s))
    }
}

private fun DrawScope.drawLeaf(
    u: Float,
    hingeX: Float,
    width: Float,
    fromLeft: Boolean,
    panel: Color,
    structure: Color,
) {
    val left = if (fromLeft) hingeX else hingeX - width
    val top = 42f
    val height = 48f
    val corner = CornerRadius(4f * u)
    drawRoundRect(panel, topLeft = Offset(left * u, top * u), size = Size(width * u, height * u), cornerRadius = corner)
    drawRoundRect(
        structure,
        topLeft = Offset(left * u, top * u),
        size = Size(width * u, height * u),
        cornerRadius = corner,
        style = Stroke(width = 3f * u),
    )
    if (width > 9f) {
        listOf(1f / 3f, 2f / 3f).forEach { fraction ->
            val x = (left + width * fraction) * u
            drawLine(structure, Offset(x, (top + 6f) * u), Offset(x, (top + height - 6f) * u), strokeWidth = 2.5f * u, cap = StrokeCap.Round)
        }
    }
}

package io.kovanica.wallet

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.Drawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.math.roundToInt

/**
 * The wallet's single source of truth for colour and the small set of shared
 * widget builders. `MainActivity` and `MessagesActivity` each keep their own
 * private helpers from before; new wallet surfaces (this file, the receive
 * screen, the token rows) build from here so the palette cannot drift.
 *
 * XML-free and dependency-free — plain `android.widget.*` on the ink surface
 * the rest of the app already uses. Coin marks are drawn here until the
 * official KUNA artwork replaces the native disc.
 */
object WalletUi {
    // Ink-toned surface. Explicit so the screen reads the same on any device theme.
    val INK = 0xFF0E1116.toInt()
    val SURFACE = 0xFF171C23.toInt()
    val SURFACE_2 = 0xFF1E242C.toInt()
    val LINE = 0xFF2A323C.toInt()
    val TEXT = 0xFFEDF1F6.toInt()
    val MUTED = 0xFF95A0AE.toInt()
    val ACCENT = 0xFFF0B429.toInt()
    val ACCENT_INK = 0xFF1A1E25.toInt()
    val ACCENT_BG = 0x1AF0B429.toInt()
    val GOOD = 0xFF5BD6A0.toInt()
    val GOOD_BG = 0x1A5BD6A0.toInt()
    val BAD = 0xFFFF7B84.toInt()
    val BAD_BG = 0x1AFF7B84.toInt()

    /** Press tint: the accent at about 18% alpha. */
    val RIPPLE = 0x2EF0B429.toInt()

    fun rounded(
        ctx: Context,
        fill: Int,
        radiusDp: Int,
        stroke: Int? = null,
        strokeDp: Int = 1,
    ): GradientDrawable = GradientDrawable().apply {
        setColor(fill)
        cornerRadius = dp(ctx, radiusDp).toFloat()
        if (stroke != null) setStroke(dp(ctx, strokeDp), stroke)
    }

    fun ripple(ctx: Context, fill: Int, radiusDp: Int): Drawable = RippleDrawable(
        ColorStateList.valueOf(RIPPLE),
        rounded(ctx, fill, radiusDp, LINE, 1),
        null,
    )

    fun dp(ctx: Context, value: Int): Int =
        (value * ctx.resources.displayMetrics.density).roundToInt()

    fun card(ctx: Context): LinearLayout = LinearLayout(ctx).apply {
        orientation = LinearLayout.VERTICAL
        background = rounded(ctx, SURFACE, 18, LINE, 1)
        setPadding(dp(ctx, 16), dp(ctx, 16), dp(ctx, 16), dp(ctx, 16))
    }

    /**
     * Round coin mark. Native KUNA is the amber "K" disc from [kunaCoin].
     * That disc is interim: the official KUNA artwork replaces it. A token
     * uses [tokenCoin], the first two letters of its symbol on a colour
     * chosen from the contract address.
     */
    fun coinMark(
        ctx: Context,
        letters: String,
        fill: Int,
        ink: Int = ACCENT_INK,
        sizeDp: Int = 36,
        description: String = letters,
    ): TextView {
        val mark = letters.trim().uppercase().filter { it.isLetterOrDigit() }.take(2).ifEmpty { "?" }
        val size = dp(ctx, sizeDp)
        return TextView(ctx).apply {
            text = mark
            contentDescription = description
            gravity = Gravity.CENTER
            includeFontPadding = false
            textSize = if (mark.length > 1) 12f else 15f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ink)
            background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(fill)
            }
            minWidth = size
            minHeight = size
        }
    }

    /** Interim native mark. Swap this view when the official KUNA logo lands. */
    fun kunaCoin(ctx: Context, sizeDp: Int = 40): TextView =
        coinMark(ctx, "K", ACCENT, ACCENT_INK, sizeDp, "KUNA")

    /** Token mark. The same contract keeps the same fill. */
    fun tokenCoin(ctx: Context, symbol: String, contract: String, sizeDp: Int = 36): TextView =
        coinMark(ctx, symbol, tokenFill(contract), ACCENT_INK, sizeDp, symbol.ifBlank { "Token" })

    private val TOKEN_FILLS = intArrayOf(
        0xFF7EB6FF.toInt(),
        0xFF5BD6A0.toInt(),
        0xFFE39A4A.toInt(),
        0xFFC9A0FF.toInt(),
        0xFF4ECDC4.toInt(),
        0xFFFF8FA3.toInt(),
    )

    /** Stable colour for a contract. Unreadable addresses fall back to a hash. */
    fun tokenFill(contract: String): Int {
        val hex = contract.trim().lowercase().removePrefix("0x")
            .filter { it in '0'..'9' || it in 'a'..'f' }
        val seed = hex.take(2).toIntOrNull(16) ?: contract.hashCode().and(0xFF)
        return TOKEN_FILLS[seed % TOKEN_FILLS.size]
    }

    fun sectionLabel(ctx: Context, caption: String, bottomPadDp: Int = 10): TextView =
        TextView(ctx).apply {
            text = caption.uppercase()
            setTextColor(MUTED)
            textSize = 11f
            letterSpacing = 0.18f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 0, dp(ctx, bottomPadDp))
        }

    fun caption(ctx: Context, text: String): TextView = TextView(ctx).apply {
        this.text = text
        setTextColor(MUTED)
        textSize = 12f
        setLineSpacing(0f, 1.3f)
    }

    fun mono(ctx: Context, text: String, size: Float = 12f): TextView = TextView(ctx).apply {
        this.text = text
        setTextColor(TEXT)
        typeface = Typeface.MONOSPACE
        textSize = size
        setTextIsSelectable(true)
        setLineSpacing(0f, 1.25f)
    }

    fun field(ctx: Context, hint: String, value: String = "", mono: Boolean = false): EditText =
        EditText(ctx).apply {
            this.hint = hint
            setText(value)
            setTextColor(TEXT)
            setHintTextColor(MUTED)
            textSize = 15f
            if (mono) typeface = Typeface.MONOSPACE
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            background = rounded(ctx, SURFACE_2, 12, LINE, 1)
            setPadding(dp(ctx, 14), dp(ctx, 13), dp(ctx, 14), dp(ctx, 13))
            maxLines = 1
        }

    fun button(
        ctx: Context,
        caption: String,
        filled: Boolean = true,
        action: () -> Unit,
    ): Button = Button(ctx).apply {
        text = caption
        isAllCaps = false
        textSize = 15f
        typeface = Typeface.DEFAULT_BOLD
        setTextColor(if (filled) ACCENT_INK else ACCENT)
        background = if (filled) rounded(ctx, ACCENT, 12) else rounded(ctx, SURFACE_2, 12, LINE, 1)
        setPadding(dp(ctx, 18), dp(ctx, 12), dp(ctx, 18), dp(ctx, 12))
        minHeight = dp(ctx, 48)
        stateListAnimator = null
        setOnClickListener { action() }
    }

    fun ViewGroup.addStack(child: View, top: Int = 0) {
        addView(
            child,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(context, top) },
        )
    }
}

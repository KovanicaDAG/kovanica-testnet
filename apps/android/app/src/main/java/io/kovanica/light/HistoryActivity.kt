package io.kovanica.light

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Typeface
import android.graphics.drawable.ColorDrawable
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.text.DateFormat
import java.util.Date
import kotlin.math.roundToInt

/**
 * Local transaction history for the selected network.
 *
 * The node has no history RPC, so this screen reads [HistoryStore] — the log
 * this phone wrote at submission time. The copy says so plainly: the list is
 * local and may include transactions that were never confirmed, so nobody
 * mistakes it for a chain-backed ledger.
 *
 * Laid out programmatically — this app has no `res/` and no Compose.
 */
class HistoryActivity : Activity() {
    private val stamps: DateFormat =
        DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)

    private lateinit var network: Network
    private lateinit var history: HistoryStore
    private lateinit var list: LinearLayout
    private lateinit var clearButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        actionBar?.hide()
        window.setBackgroundDrawable(ColorDrawable(WalletUi.INK))
        window.statusBarColor = WalletUi.INK

        network = NetworkPrefs.selected(this)
        history = HistoryStore(this)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(24), dp(20), dp(36))
            setBackgroundColor(WalletUi.INK)
            addStack(header())
            addView(
                View(this@HistoryActivity).apply {
                    background = WalletUi.rounded(this@HistoryActivity, WalletUi.ACCENT, 2)
                },
                LinearLayout.LayoutParams(dp(40), dp(3)).apply { topMargin = dp(14) },
            )
            addStack(legend(), 18)

            list = LinearLayout(this@HistoryActivity).apply {
                orientation = LinearLayout.VERTICAL
            }
            addStack(list, 0)

            clearButton = WalletUi.button(this@HistoryActivity, "Clear history", filled = false) {
                confirmClear()
            }.apply { setTextColor(WalletUi.BAD) }
            addStack(clearButton, 18)

            addStack(WalletUi.button(this@HistoryActivity, "Back to wallet") { finish() }, 10)
        }

        setContentView(ScrollView(this).apply {
            isFillViewport = true
            setBackgroundColor(WalletUi.INK)
            addView(root)
        })

        render()
    }

    // --- content -------------------------------------------------------------------------

    private fun render() {
        val entries = history.entries(network.id)
        list.removeAllViews()
        clearButton.visibility = if (entries.isEmpty()) View.GONE else View.VISIBLE

        if (entries.isEmpty()) {
            list.addStack(
                TextView(this).apply {
                    text = "No transactions on ${network.label} yet."
                    setTextColor(WalletUi.MUTED)
                    textSize = 13f
                    setLineSpacing(0f, 1.3f)
                },
                0,
            )
            return
        }

        entries.forEachIndexed { index, entry ->
            list.addStack(entryRow(entry), if (index == 0) 0 else 10)
        }
    }

    private fun legend(): LinearLayout = WalletUi.card(this).apply {
        addStack(WalletUi.sectionLabel(this@HistoryActivity, "Local history"))
        addStack(
            WalletUi.caption(
                this@HistoryActivity,
                "What this phone sent on ${network.label}. The node has no history API, so " +
                    "entries are written here the moment you submit — they can include " +
                    "transactions that were never confirmed or were rejected by the network.",
            ),
            0,
        )
        addStack(
            WalletUi.caption(
                this@HistoryActivity,
                "Newest first, kept on this phone only. Clearing the list does not affect the " +
                    "chain or your wallet.",
            ),
            10,
        )
    }

    /** One history entry: kind badge, amount, counterparty, time, and the tx hash. */
    private fun entryRow(entry: HistoryEntry): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = WalletUi.rounded(this@HistoryActivity, WalletUi.SURFACE, 16, WalletUi.LINE, 1)
        setPadding(dp(14), dp(13), dp(14), dp(13))

        val head = LinearLayout(this@HistoryActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        head.addView(kindBadge(entry.kind))
        head.addView(
            TextView(this@HistoryActivity).apply {
                text = stamps.format(Date(entry.timestampMs))
                setTextColor(WalletUi.MUTED)
                textSize = 11f
                gravity = Gravity.END
            },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
        )
        addView(head)

        val amountRow = LinearLayout(this@HistoryActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(8), 0, 0)
        }
        amountRow.addView(
            coinFor(entry),
            LinearLayout.LayoutParams(dp(28), dp(28)),
        )
        amountRow.addView(
            TextView(this@HistoryActivity).apply {
                text = amountLine(entry)
                setTextColor(WalletUi.TEXT)
                textSize = 18f
                typeface = Typeface.DEFAULT_BOLD
            },
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { leftMargin = dp(10) },
        )
        addView(amountRow)

        counterpartyLine(entry)?.let { line ->
            addView(TextView(this@HistoryActivity).apply {
                text = line
                setTextColor(WalletUi.MUTED)
                textSize = 12f
                typeface = Typeface.MONOSPACE
                setPadding(0, dp(4), 0, 0)
            })
        }

        addView(TextView(this@HistoryActivity).apply {
            text = "tx ${shortHash(entry.hash)}"
            setTextColor(WalletUi.MUTED)
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setPadding(0, dp(4), 0, 0)
        })
    }

    // --- small pieces --------------------------------------------------------------------

    private fun kindBadge(kind: String): TextView {
        val (foreground, background) = kindColors(kind)
        return TextView(this).apply {
            text = kindLabel(kind)
            setTextColor(foreground)
            textSize = 10f
            letterSpacing = 0.14f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(dp(8), dp(3), dp(8), dp(3))
            this.background = WalletUi.rounded(this@HistoryActivity, background, 8)
        }
    }

    private fun kindLabel(kind: String): String = when (kind) {
        HistoryEntry.KIND_SEND -> "SENT"
        HistoryEntry.KIND_TOKEN_SEND -> "TOKEN"
        HistoryEntry.KIND_BOND -> "BOND"
        HistoryEntry.KIND_WITNESS -> "WITNESS"
        HistoryEntry.KIND_EXIT -> "EXIT"
        HistoryEntry.KIND_FAUCET -> "FAUCET"
        HistoryEntry.KIND_TOKEN_CREATE -> "TOKEN NEW"
        else -> kind.uppercase()
    }

    private fun kindColors(kind: String): Pair<Int, Int> = when (kind) {
        HistoryEntry.KIND_FAUCET -> WalletUi.GOOD to WalletUi.GOOD_BG
        else -> WalletUi.ACCENT to WalletUi.ACCENT_BG
    }

    private fun coinFor(entry: HistoryEntry): TextView {
        val symbol = entry.symbol
        return if (symbol.isNullOrBlank() || symbol.equals("KUNA", ignoreCase = true)) {
            WalletUi.kunaCoin(this, 28)
        } else {
            WalletUi.tokenCoin(this, symbol, entry.contract ?: symbol, 28)
        }
    }

    private fun amountLine(entry: HistoryEntry): String {
        val amount = entry.amount ?: return "—"
        val symbol = entry.symbol
        return if (symbol.isNullOrBlank()) amount else "$amount $symbol"
    }

    private fun counterpartyLine(entry: HistoryEntry): String? {
        val to = entry.to?.let { "to ${KvncAddress.short(it)}" }
        val contract = entry.contract?.let { "token ${KvncAddress.short(it)}" }
        return listOfNotNull(to, contract).joinToString("  ·  ").ifEmpty { null }
    }

    private fun shortHash(hash: String): String {
        val value = hash.trim()
        return if (value.length <= 24) value else "${value.take(14)}…${value.takeLast(8)}"
    }

    private fun confirmClear() {
        AlertDialog.Builder(this)
            .setTitle("Clear history?")
            .setMessage(
                "This removes the local list on ${network.label} from this phone. " +
                    "It does not touch the chain or your wallet.",
            )
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Clear") { _, _ ->
                history.clear(network.id)
                render()
            }
            .show()
    }

    private fun header(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(TextView(this@HistoryActivity).apply {
            text = "Kovanica · HISTORY"
            setTextColor(WalletUi.ACCENT)
            textSize = 11f
            letterSpacing = 0.22f
            typeface = Typeface.DEFAULT_BOLD
        })
        addView(TextView(this@HistoryActivity).apply {
            text = "History"
            setTextColor(WalletUi.TEXT)
            textSize = 30f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, dp(6), 0, 0)
        })
        addView(TextView(this@HistoryActivity).apply {
            text = "A local record of what this phone submitted."
            setTextColor(WalletUi.MUTED)
            textSize = 13f
            setLineSpacing(0f, 1.3f)
            setPadding(0, dp(8), 0, 0)
        })
    }

    private fun ViewGroup.addStack(child: View, top: Int = 0) {
        addView(
            child,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(top) },
        )
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).roundToInt()
}

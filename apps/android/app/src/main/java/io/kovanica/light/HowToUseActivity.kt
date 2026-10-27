package io.kovanica.light

import android.app.Activity
import android.graphics.Typeface
import android.graphics.drawable.ColorDrawable
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import kotlin.math.roundToInt

/**
 * The in-app guide. A plain-language walkthrough of every screen, written to
 * match the buttons a user actually taps on the home screen — no marketing
 * copy. It holds no wallet state and talks to nothing: it only lays out text.
 *
 * Laid out programmatically — this app has no `res/` and no Compose.
 */
class HowToUseActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        actionBar?.hide()
        window.setBackgroundDrawable(ColorDrawable(WalletUi.INK))
        window.statusBarColor = WalletUi.INK

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(24), dp(20), dp(36))
            setBackgroundColor(WalletUi.INK)
        }

        root.addView(header())
        root.addView(
            View(this).apply { background = WalletUi.rounded(this@HowToUseActivity, WalletUi.ACCENT, 2) },
            LinearLayout.LayoutParams(dp(40), dp(3)).apply { topMargin = dp(14) },
        )

        root.addStack(introCard(), 18)

        root.addStack(
            step(
                number = 1,
                title = "Pick your network",
                body = "Open the Node tab, or tap the network chip at the top right. Local and " +
                    "Testnet are ready to use; Mainnet is listed but greyed out until it opens. " +
                    "The RPC endpoint, chain id, and faucet fill in automatically — you can edit " +
                    "them if you run your own node. Your choice is remembered for next time.",
            ),
            14,
        )

        root.addStack(
            step(
                number = 2,
                title = "Create or import a wallet",
                body = "On the Account tab, type a passphrase in the field at the top, then tap " +
                    "Create wallet. Or paste your 24-word seed and tap Import wallet. Your seed " +
                    "words and passphrase stay on this phone and are never sent to a node.",
                tip = "When you create a wallet the seed is shown once. Write it down and keep " +
                    "it somewhere safe — it is the only way to recover your funds.",
            ),
            14,
        )

        root.addStack(
            step(
                number = 3,
                title = "Check the connection",
                body = "On the Node tab, tap Check connection to read the chain head and your " +
                    "balance from the node you selected. Sync sealed header pulls the latest " +
                    "sealed header, and Verified balance checks a node's answer against that " +
                    "header before you trust it.",
            ),
            14,
        )

        root.addStack(
            step(
                number = 4,
                title = "Receive KUNA",
                body = "On the Wallet tab, tap Receive to show your address and a QR code, then " +
                    "copy or share it. Anyone can pay you at that address. Receiving is free " +
                    "and needs no passphrase.",
            ),
            14,
        )

        root.addStack(
            step(
                number = 5,
                title = "Send KUNA",
                body = "On the Wallet tab, paste the recipient's address, enter the amount in " +
                    "atoms (1 KUNA is 1,000,000,000 atoms), and tap Send. Before anything is " +
                    "signed, a review step shows the recipient, the amount, and the network " +
                    "fee. Confirm it, and the passphrase at the top unlocks the key on this " +
                    "phone.",
            ),
            14,
        )

        root.addStack(
            step(
                number = 6,
                title = "Get testnet KUNA",
                body = "On the Node tab, on a network that has a faucet, tap Request faucet to " +
                    "ask for test coins at your address. The button only appears on those " +
                    "networks — Mainnet has no faucet.",
            ),
            14,
        )

        root.addStack(
            step(
                number = 7,
                title = "Watch and send tokens",
                body = "Native KUNA lives in your balance; KVP-102 tokens live in their own " +
                    "contracts. On the Wallet tab, in the Tokens card, tap Add and paste a " +
                    "token's contract " +
                    "address to watch it — the app reads the symbol, supply, and your balance " +
                    "straight from the contract. Tap Create token to deploy your own. Tap a " +
                    "token row to open its send panel and move tokens in the token's base " +
                    "units. Long-press a token, or tap Stop watching, to remove it — that only " +
                    "clears it from this phone. The list is kept per network.",
                tip = "Token amounts are separate from your KUNA balance and never count " +
                    "towards it.",
            ),
            14,
        )

        root.addStack(
            step(
                number = 8,
                title = "Join as a light node",
                body = "On the Node tab, tap Bond 100 KUNA to register this phone as a " +
                    "light node, and Submit witness once per epoch. Exit light node unbonds you " +
                    "and returns your stake. Each of those asks you to confirm before anything " +
                    "is signed. A desktop kovanica-lightnode can submit the witness while the " +
                    "phone sleeps, so opening the app about once a day is enough.",
            ),
            14,
        )

        root.addStack(
            step(
                number = 9,
                title = "Send sealed messages",
                body = "On the Account tab, tap Open Messages to chat one-to-one. Messages are " +
                    "sealed on this phone " +
                    "and travel through your own relay, which only ever stores ciphertext. Set " +
                    "the relay address, unlock with your passphrase, then add contacts by name " +
                    "or public key.",
            ),
            14,
        )

        root.addStack(
            step(
                number = 10,
                title = "Check your transaction history",
                body = "On the Account tab, tap Transaction history to see a local record of " +
                    "what this phone has " +
                    "sent: transfers, token moves, light-node bond, witness, and exit, plus " +
                    "faucet requests. The log is kept on this phone, so it is there before " +
                    "the node answers.",
            ),
            14,
        )

        root.addStack(
            step(
                number = 11,
                title = "Back up your seed in Settings",
                body = "On the Account tab, tap Settings to manage the passphrase that unlocks " +
                    "this phone and to " +
                    "back up your 24-word seed. Your seed is the only way to recover your " +
                    "funds, so write it down and keep it offline.",
            ),
            14,
        )

        root.addStack(keysCard(), 18)
        root.addStack(WalletUi.button(this, "Back to wallet") { finish() }, 22)

        setContentView(ScrollView(this).apply {
            isFillViewport = true
            setBackgroundColor(WalletUi.INK)
            addView(root)
        })
    }

    // --- content -------------------------------------------------------------------------

    private fun introCard(): LinearLayout = WalletUi.card(this).apply {
        addStack(WalletUi.sectionLabel(this@HowToUseActivity, "Start here"))
        addStack(
            WalletUi.caption(
                this@HowToUseActivity,
                "This is a light client: it keeps your keys on the phone and reads the chain " +
                    "through a node you choose. Home has three tabs — Wallet, Node, and " +
                    "Account. The passphrase at the top unlocks this phone and never leaves it.",
            ),
            0,
        )
    }

    /** One numbered step, rendered as a card that matches the rest of the app. */
    private fun step(number: Int, title: String, body: String, tip: String? = null): LinearLayout =
        WalletUi.card(this).apply {
            val head = LinearLayout(this@HowToUseActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            head.addView(
                numberBadge(number),
                LinearLayout.LayoutParams(dp(34), dp(34)),
            )
            head.addView(
                TextView(this@HowToUseActivity).apply {
                    text = title
                    setTextColor(WalletUi.TEXT)
                    textSize = 17f
                    typeface = Typeface.DEFAULT_BOLD
                    setLineSpacing(0f, 1.2f)
                    setPadding(dp(12), 0, 0, 0)
                },
                LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
            )
            addStack(head, 0)
            addStack(WalletUi.caption(this@HowToUseActivity, body), 12)
            if (tip != null) addStack(tipView(tip), 12)
        }

    private fun keysCard(): LinearLayout = WalletUi.card(this).apply {
        addStack(WalletUi.sectionLabel(this@HowToUseActivity, "Keys stay on your phone"))
        addStack(
            WalletUi.caption(
                this@HowToUseActivity,
                "Your seed words and passphrase never leave this phone and are never sent to a " +
                    "node or a relay. Anyone with your seed controls your KUNA, so keep it " +
                    "offline and share it with no one. An address, by contrast, is safe to share.",
            ),
            0,
        )
        addStack(
            WalletUi.caption(
                this@HowToUseActivity,
                "Because this is a light client, the app relies on the node you selected to " +
                    "read the chain. Use Verified balance when you want to check a node's " +
                    "answer against a sealed header.",
            ),
            10,
        )
    }

    // --- small pieces --------------------------------------------------------------------

    private fun numberBadge(value: Int): TextView = TextView(this).apply {
        text = value.toString()
        setTextColor(WalletUi.ACCENT_INK)
        textSize = 14f
        typeface = Typeface.DEFAULT_BOLD
        gravity = Gravity.CENTER
        background = WalletUi.rounded(this@HowToUseActivity, WalletUi.ACCENT, 18)
    }

    private fun tipView(text: String): TextView = TextView(this).apply {
        this.text = text
        setTextColor(WalletUi.ACCENT)
        textSize = 12f
        setLineSpacing(0f, 1.3f)
        background = WalletUi.rounded(this@HowToUseActivity, WalletUi.ACCENT_BG, 12)
        setPadding(dp(12), dp(10), dp(12), dp(10))
    }

    private fun header(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(TextView(this@HowToUseActivity).apply {
            text = "Kovanica · GUIDE"
            setTextColor(WalletUi.ACCENT)
            textSize = 11f
            letterSpacing = 0.22f
            typeface = Typeface.DEFAULT_BOLD
        })
        addView(TextView(this@HowToUseActivity).apply {
            text = "How to use"
            setTextColor(WalletUi.TEXT)
            textSize = 30f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, dp(6), 0, 0)
        })
        addView(TextView(this@HowToUseActivity).apply {
            text = "Plain steps for every screen. Your keys stay on this phone."
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

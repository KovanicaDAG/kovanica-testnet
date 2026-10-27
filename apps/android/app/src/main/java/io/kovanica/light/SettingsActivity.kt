package io.kovanica.light

import android.app.Activity
import android.graphics.Typeface
import android.graphics.drawable.ColorDrawable
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import uniffi.kovanica_light.changePassphraseRaw
import uniffi.kovanica_light.revealMnemonicRaw
import java.util.concurrent.Executors
import kotlin.math.roundToInt

/**
 * Wallet settings: back up the seed phrase, change the passphrase, and read the
 * app version.
 *
 * Both the reveal and the re-encrypt run on a background thread because the
 * keystore is protected with Argon2id — decrypting it on the UI thread would
 * freeze the screen. A wrong passphrase comes back as a normal error line here,
 * never a crash. Nothing secret is ever put in the status banner.
 *
 * Laid out programmatically — this app has no `res/` and no Compose.
 */
class SettingsActivity : Activity() {
    private val io = Executors.newSingleThreadExecutor()

    private lateinit var status: TextView
    private lateinit var seedPassField: EditText
    private lateinit var currentPassField: EditText
    private lateinit var newPassField: EditText
    private lateinit var confirmPassField: EditText
    private lateinit var revealButton: Button
    private lateinit var changeButton: Button
    private lateinit var seedBox: ScrollView
    private lateinit var seedText: TextView
    private lateinit var seedWarning: TextView
    private lateinit var hideButton: Button

    private var busy = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        actionBar?.hide()
        window.setBackgroundDrawable(ColorDrawable(WalletUi.INK))
        window.statusBarColor = WalletUi.INK

        status = TextView(this).apply {
            textSize = 13f
            setLineSpacing(0f, 1.3f)
            setPadding(dp(14), dp(12), dp(14), dp(12))
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(24), dp(20), dp(36))
            setBackgroundColor(WalletUi.INK)
            addStack(header())
            addView(
                View(this@SettingsActivity).apply {
                    background = WalletUi.rounded(this@SettingsActivity, WalletUi.ACCENT, 2)
                },
                LinearLayout.LayoutParams(dp(40), dp(3)).apply { topMargin = dp(14) },
            )
            addStack(status, 18)
            addStack(seedCard(), 18)
            addStack(passphraseCard(), 18)
            addStack(aboutCard(), 18)
            addStack(WalletUi.button(this@SettingsActivity, "Back to wallet") { finish() }, 10)
        }

        setContentView(ScrollView(this).apply {
            isFillViewport = true
            setBackgroundColor(WalletUi.INK)
            addView(root)
        })

        setStatus(
            if (keystoreOrNull() == null) {
                "No wallet on this phone yet — create or import one on the home screen first."
            } else {
                "Back up your seed phrase, or change the passphrase that unlocks it."
            },
            if (keystoreOrNull() == null) Tone.WARN else Tone.NEUTRAL,
        )
    }

    override fun onStop() {
        super.onStop()
        // Clear the revealed seed, and any typed passphrase, on the way out.
        hideSeed()
        if (::seedPassField.isInitialized) seedPassField.setText("")
        if (::currentPassField.isInitialized) currentPassField.setText("")
        if (::newPassField.isInitialized) newPassField.setText("")
        if (::confirmPassField.isInitialized) confirmPassField.setText("")
    }

    override fun onDestroy() {
        io.shutdown()
        super.onDestroy()
    }

    // --- seed backup ---------------------------------------------------------------------

    private fun seedCard(): LinearLayout = WalletUi.card(this).apply {
        addStack(WalletUi.sectionLabel(this@SettingsActivity, "Seed backup"))
        addStack(
            WalletUi.caption(
                this@SettingsActivity,
                "Your 24-word seed is the only way to recover this wallet. It is stored " +
                    "encrypted on this phone; enter your passphrase to reveal it.",
            ),
            0,
        )

        seedPassField = passField("Passphrase")
        addStack(seedPassField, 12)

        revealButton = WalletUi.button(this@SettingsActivity, "Show seed phrase") { revealSeed() }
        addStack(revealButton, 10)

        seedWarning = TextView(this@SettingsActivity).apply {
            text = "Anyone with these words controls your KUNA. Never share them and never type " +
                "them into a website or app. Write them down offline and keep them safe."
            setTextColor(WalletUi.BAD)
            textSize = 12f
            setLineSpacing(0f, 1.3f)
            background = WalletUi.rounded(this@SettingsActivity, WalletUi.BAD_BG, 12)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            visibility = View.GONE
        }
        addStack(seedWarning, 12)

        seedText = WalletUi.mono(this@SettingsActivity, "", 15f)
        seedBox = ScrollView(this@SettingsActivity).apply {
            visibility = View.GONE
            background = WalletUi.rounded(this@SettingsActivity, WalletUi.SURFACE_2, 12, WalletUi.LINE, 1)
            setPadding(dp(14), dp(12), dp(14), dp(12))
            isFillViewport = false
            addView(seedText)
        }
        addView(
            seedBox,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(170),
            ).apply { topMargin = dp(12) },
        )

        hideButton = WalletUi.button(this@SettingsActivity, "Hide seed phrase", filled = false) {
            hideSeed()
        }
        hideButton.visibility = View.GONE
        addStack(hideButton, 10)
    }

    /**
     * Outcome of a background reveal. The mnemonic travels in [Shown] only; it is
     * never routed through the status banner.
     */
    private sealed interface Reveal {
        data class Shown(val mnemonic: String) : Reveal
        data class Failed(val message: String) : Reveal
    }

    private fun revealSeed() {
        if (busy) return
        val keystore = keystoreOrNull()
        if (keystore == null) {
            setStatus("Create or import a wallet first — there's no seed to show.", Tone.WARN)
            return
        }
        val passphrase = seedPassField.text.toString()
        if (passphrase.isEmpty()) {
            setStatus("Enter your passphrase to reveal the seed phrase.", Tone.ERROR)
            return
        }

        setBusy(true, "Decrypting your wallet — this takes a moment…", Tone.NEUTRAL)
        io.execute {
            val result = try {
                Reveal.Shown(revealMnemonicRaw(keystore, passphrase))
            } catch (error: Exception) {
                Reveal.Failed(error.message ?: "Couldn't reveal the seed phrase.")
            }
            runOnUiThread {
                setBusy(false)
                when (result) {
                    is Reveal.Shown -> {
                        seedText.text = result.mnemonic
                        seedBox.visibility = View.VISIBLE
                        seedWarning.visibility = View.VISIBLE
                        hideButton.visibility = View.VISIBLE
                        seedPassField.setText("")
                        setStatus(
                            "Seed phrase shown below. Write it down offline — never share it.",
                            Tone.WARN,
                        )
                    }
                    is Reveal.Failed -> setStatus(result.message, Tone.ERROR)
                }
            }
        }
    }

    private fun hideSeed() {
        if (::seedText.isInitialized) seedText.text = ""
        if (::seedBox.isInitialized) seedBox.visibility = View.GONE
        if (::seedWarning.isInitialized) seedWarning.visibility = View.GONE
        if (::hideButton.isInitialized) hideButton.visibility = View.GONE
    }

    // --- change passphrase ---------------------------------------------------------------

    private fun passphraseCard(): LinearLayout = WalletUi.card(this).apply {
        addStack(WalletUi.sectionLabel(this@SettingsActivity, "Change passphrase"))
        addStack(
            WalletUi.caption(
                this@SettingsActivity,
                "Re-encrypts the wallet on this phone. Your seed and address do not change, so " +
                    "nothing else needs updating.",
            ),
            0,
        )

        currentPassField = passField("Current passphrase")
        addStack(currentPassField, 12)
        newPassField = passField("New passphrase")
        addStack(newPassField, 8)
        confirmPassField = passField("Confirm new passphrase")
        addStack(confirmPassField, 8)

        addStack(
            WalletUi.button(this@SettingsActivity, "Change passphrase") { changePassphrase() }
                .also { changeButton = it },
            12,
        )
    }

    /** Outcome of a background re-encrypt; [Done] carries the new keystore to store. */
    private sealed interface Change {
        data class Done(val keystoreJson: String) : Change
        data class Failed(val message: String) : Change
    }

    private fun changePassphrase() {
        if (busy) return
        val keystore = keystoreOrNull()
        if (keystore == null) {
            setStatus("Create or import a wallet first — there's nothing to re-encrypt.", Tone.WARN)
            return
        }
        val current = currentPassField.text.toString()
        val next = newPassField.text.toString()
        val confirm = confirmPassField.text.toString()
        if (current.isEmpty()) {
            setStatus("Enter your current passphrase.", Tone.ERROR)
            return
        }
        if (next.isEmpty()) {
            setStatus("Enter a new passphrase.", Tone.ERROR)
            return
        }
        if (next != confirm) {
            setStatus("The new passphrase and its confirmation don't match.", Tone.ERROR)
            return
        }

        setBusy(true, "Re-encrypting your wallet — this takes a moment…", Tone.NEUTRAL)
        io.execute {
            val result = try {
                Change.Done(changePassphraseRaw(keystore, current, next))
            } catch (error: Exception) {
                Change.Failed(error.message ?: "Couldn't change the passphrase.")
            }
            runOnUiThread {
                setBusy(false)
                when (result) {
                    is Change.Done -> {
                        prefs().edit().putString("keystore", result.keystoreJson).apply()
                        currentPassField.setText("")
                        newPassField.setText("")
                        confirmPassField.setText("")
                        setStatus(
                            "Passphrase changed. Your seed and address are unchanged.",
                            Tone.OK,
                        )
                    }
                    is Change.Failed -> setStatus(result.message, Tone.ERROR)
                }
            }
        }
    }

    // --- about ---------------------------------------------------------------------------

    private fun aboutCard(): LinearLayout = WalletUi.card(this).apply {
        addStack(WalletUi.sectionLabel(this@SettingsActivity, "About"))
        addStack(aboutRow("App", "Kovanica Lightnode"), 0)
        addStack(
            aboutRow("Version", "${BuildConfig.VERSION_NAME} (build ${BuildConfig.VERSION_CODE})"),
            8,
        )
        addStack(
            WalletUi.caption(
                this@SettingsActivity,
                "A light client: your keys stay on this phone; a node you choose reads the chain.",
            ),
            12,
        )
    }

    private fun aboutRow(label: String, value: String): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        addView(
            TextView(this@SettingsActivity).apply {
                text = label
                setTextColor(WalletUi.MUTED)
                textSize = 13f
            },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
        )
        addView(
            TextView(this@SettingsActivity).apply {
                text = value
                setTextColor(WalletUi.TEXT)
                textSize = 13f
                typeface = Typeface.DEFAULT_BOLD
            },
        )
    }

    // --- plumbing ------------------------------------------------------------------------

    private enum class Tone { NEUTRAL, OK, WARN, ERROR }

    private fun setStatus(text: String, tone: Tone) {
        status.text = text
        val (foreground, background) = when (tone) {
            Tone.NEUTRAL -> WalletUi.MUTED to WalletUi.SURFACE
            Tone.OK -> WalletUi.GOOD to WalletUi.GOOD_BG
            Tone.WARN -> WalletUi.ACCENT to WalletUi.ACCENT_BG
            Tone.ERROR -> WalletUi.BAD to WalletUi.BAD_BG
        }
        status.setTextColor(foreground)
        status.background = WalletUi.rounded(this, background, 14, WalletUi.LINE, 1)
    }

    /** Dim the two action buttons while a decrypt is in flight, so it can't be double-fired. */
    private fun setBusy(working: Boolean, label: String? = null, tone: Tone = Tone.NEUTRAL) {
        busy = working
        listOf(revealButton, changeButton).forEach {
            it.isEnabled = !working
            it.alpha = if (working) 0.5f else 1f
        }
        if (label != null) setStatus(label, tone)
    }

    private fun passField(hint: String): EditText = WalletUi.field(this, hint).apply {
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
    }

    private fun prefs() = getSharedPreferences(HistoryStore.PREFS, MODE_PRIVATE)

    private fun keystoreOrNull(): String? = prefs().getString("keystore", null)

    private fun header(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(TextView(this@SettingsActivity).apply {
            text = "Kovanica · SETTINGS"
            setTextColor(WalletUi.ACCENT)
            textSize = 11f
            letterSpacing = 0.22f
            typeface = Typeface.DEFAULT_BOLD
        })
        addView(TextView(this@SettingsActivity).apply {
            text = "Settings"
            setTextColor(WalletUi.TEXT)
            textSize = 30f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, dp(6), 0, 0)
        })
        addView(TextView(this@SettingsActivity).apply {
            text = "Back up your seed phrase, or change the passphrase that unlocks it."
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

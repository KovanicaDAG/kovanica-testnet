package io.kovanica.light

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.Drawable
import android.graphics.drawable.RippleDrawable
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import kotlin.math.roundToInt

/**
 * The contact list: save the addresses you pay often, so a send is a tap
 * instead of a 70-character paste.
 *
 * Opened from the send card with [EXTRA_PICK] set, a tap on a row returns that
 * address to [MainActivity] through the classic `setResult` contract — this app
 * carries no androidx, so there is no activity-result API to lean on. The same
 * screen also adds and removes entries, so a new contact can be saved without
 * leaving the send flow.
 *
 * Nothing here signs or talks to the network. It reads and writes a realm of the
 * `"kvnc"` SharedPreferences file and nothing else.
 *
 * Laid out programmatically — this app has no `res/` and no Compose.
 */
class AddressBookActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var labelField: EditText
    private lateinit var addressField: EditText
    private lateinit var validation: TextView
    private lateinit var contactsList: LinearLayout

    private lateinit var store: AddressBookStore
    private var pickMode = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        actionBar?.hide()
        window.setBackgroundDrawable(ColorDrawable(WalletUi.INK))
        window.statusBarColor = WalletUi.INK

        store = AddressBookStore(this)
        pickMode = intent.getBooleanExtra(EXTRA_PICK, false)

        status = TextView(this).apply {
            textSize = 13f
            setLineSpacing(0f, 1.3f)
            setPadding(dp(14), dp(12), dp(14), dp(12))
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(24), dp(20), dp(36))
            setBackgroundColor(WalletUi.INK)
        }

        root.addView(header())
        root.addView(
            View(this).apply { background = WalletUi.rounded(this@AddressBookActivity, WalletUi.ACCENT, 2) },
            LinearLayout.LayoutParams(dp(40), dp(3)).apply { topMargin = dp(14) },
        )
        root.addStack(status, 18)

        root.addStack(addCard(), 18)
        root.addStack(listCard(), 18)
        root.addStack(
            WalletUi.button(this, "Back to wallet", filled = false) { finish() },
            18,
        )

        setContentView(ScrollView(this).apply {
            isFillViewport = true
            setBackgroundColor(WalletUi.INK)
            addView(root)
        })

        setStatus(
            if (pickMode) "Tap an address to fill the send field." else "Saved recipients, kept on this phone only.",
            Tone.NEUTRAL,
        )
        render()
    }

    // --- cards ---------------------------------------------------------------------------

    private fun addCard(): LinearLayout = WalletUi.card(this).apply {
        addStack(WalletUi.sectionLabel(this@AddressBookActivity, "Add a contact"))
        labelField = WalletUi.field(this@AddressBookActivity, "Label, e.g. Ana")
        addStack(labelField)
        addressField = WalletUi.field(this@AddressBookActivity, "Address", mono = true)
        addStack(addressField, 8)
        validation = TextView(this@AddressBookActivity).apply {
            textSize = 12f
            setLineSpacing(0f, 1.3f)
            visibility = View.GONE
        }
        addStack(validation, 8)
        addStack(WalletUi.button(this@AddressBookActivity, "Save contact") { addContact() }, 12)
        addStack(
            WalletUi.caption(
                this@AddressBookActivity,
                "Paste a kvnc…dag address or its 64 hex characters. The address is checked here " +
                    "before it is saved.",
            ),
            12,
        )

        // Validate as they type, so a bad address is caught before Save is reached.
        addressField.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                validateAddress()
            }
        })
    }

    private fun listCard(): LinearLayout = WalletUi.card(this).apply {
        addStack(WalletUi.sectionLabel(this@AddressBookActivity, "Saved contacts"))
        contactsList = LinearLayout(this@AddressBookActivity).apply {
            orientation = LinearLayout.VERTICAL
        }
        addStack(contactsList, 0)
    }

    // --- actions -------------------------------------------------------------------------

    /** Returns true when the field currently holds a usable address. */
    private fun validateAddress(): Boolean {
        val raw = addressField.text.toString().trim()
        when {
            raw.isEmpty() -> {
                validation.visibility = View.GONE
                return false
            }
            KvncAddress.isValid(raw, NetworkPrefs.chainId(this)) -> {
                validation.text = "Looks good — saves as ${KvncAddress.short(raw)}."
                validation.setTextColor(WalletUi.GOOD)
                validation.visibility = View.VISIBLE
                return true
            }
            else -> {
                validation.text = "That is not a Kovanica address. Check for a missing or extra character."
                validation.setTextColor(WalletUi.BAD)
                validation.visibility = View.VISIBLE
                return false
            }
        }
    }

    private fun addContact() {
        val label = labelField.text.toString().trim()
        val raw = addressField.text.toString().trim()
        if (label.isEmpty()) {
            setStatus("Give the contact a label first.", Tone.ERROR)
            return
        }
        if (!KvncAddress.isValid(raw, NetworkPrefs.chainId(this))) {
            setStatus("That is not a Kovanica address. Check it and try again.", Tone.ERROR)
            return
        }
        val hex = KvncAddress.normalizeHex(raw, NetworkPrefs.chainId(this)) ?: return
        val already = store.list().any { it.address == hex }
        if (!store.add(label, hex)) {
            setStatus("Couldn't save that contact.", Tone.ERROR)
            return
        }
        labelField.setText("")
        addressField.setText("")
        render()
        setStatus(
            if (already) "Updated the label for that address." else "Saved $label to your contacts.",
            Tone.OK,
        )
    }

    private fun pick(entry: AddressBookEntry) {
        setResult(
            RESULT_OK,
            Intent().putExtra(EXTRA_RESULT_ADDRESS, KvncAddress.display(entry.address)),
        )
        finish()
    }

    private fun confirmRemove(entry: AddressBookEntry) {
        AlertDialog.Builder(this)
            .setTitle("Remove contact?")
            .setMessage(
                "Remove ${entry.label} (${KvncAddress.short(entry.address)}) from this phone? " +
                    "This only changes this list — it does not touch the chain or your wallet.",
            )
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Remove") { _, _ ->
                if (store.remove(entry.address)) {
                    render()
                    setStatus("Removed ${entry.label}.", Tone.OK)
                }
            }
            .show()
    }

    // --- rendering -----------------------------------------------------------------------

    private fun render() {
        val entries = store.list()
        contactsList.removeAllViews()
        if (entries.isEmpty()) {
            contactsList.addStack(
                WalletUi.caption(
                    this,
                    if (pickMode) {
                        "No saved contacts yet. Add one above, or go back and type the address."
                    } else {
                        "No saved contacts yet. Add one above."
                    },
                ),
                2,
            )
            return
        }
        entries.forEachIndexed { index, entry ->
            contactsList.addStack(contactRow(entry), if (index == 0) 2 else 8)
        }
    }

    private fun contactRow(entry: AddressBookEntry): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(dp(14), dp(12), dp(14), dp(12))
        background = if (pickMode) rowBackground() else WalletUi.rounded(this@AddressBookActivity, WalletUi.SURFACE_2, 12)
        if (pickMode) {
            isClickable = true
            isFocusable = true
            setOnClickListener { pick(entry) }
        }

        val details = LinearLayout(this@AddressBookActivity).apply {
            orientation = LinearLayout.VERTICAL
            addView(TextView(this@AddressBookActivity).apply {
                text = entry.label
                setTextColor(WalletUi.TEXT)
                textSize = 15f
                typeface = Typeface.DEFAULT_BOLD
            })
            addView(TextView(this@AddressBookActivity).apply {
                text = KvncAddress.short(entry.address)
                setTextColor(WalletUi.MUTED)
                typeface = Typeface.MONOSPACE
                textSize = 12f
                setPadding(0, dp(3), 0, 0)
            })
        }
        addView(
            details,
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
        )

        addView(TextView(this@AddressBookActivity).apply {
            text = "Remove"
            setTextColor(WalletUi.BAD)
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(dp(12), dp(8), dp(4), dp(8))
            isClickable = true
            isFocusable = true
            setOnClickListener { confirmRemove(entry) }
        })
    }

    /** Press tint over the row's own chip; no border, so rows inside a card stay quiet. */
    private fun rowBackground(): Drawable = RippleDrawable(
        ColorStateList.valueOf(WalletUi.RIPPLE),
        WalletUi.rounded(this, WalletUi.SURFACE_2, 12),
        null,
    )

    // --- chrome --------------------------------------------------------------------------

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

    private fun header(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(TextView(this@AddressBookActivity).apply {
            text = "KVNC · CONTACTS"
            setTextColor(WalletUi.ACCENT)
            textSize = 11f
            letterSpacing = 0.22f
            typeface = Typeface.DEFAULT_BOLD
        })
        addView(TextView(this@AddressBookActivity).apply {
            text = "Contacts"
            setTextColor(WalletUi.TEXT)
            textSize = 30f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, dp(6), 0, 0)
        })
        addView(TextView(this@AddressBookActivity).apply {
            text = if (pickMode) {
                "Tap a saved address to put it in the send field."
            } else {
                "Addresses you pay often, saved on this phone."
            }
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

    companion object {
        /** Set true to open the screen as a picker that returns a chosen address. */
        const val EXTRA_PICK: String = "io.kovanica.light.ADDRESS_BOOK_PICK"

        /** The chosen address, in `kvnc…dag` display form, when [RESULT_OK]. */
        const val EXTRA_RESULT_ADDRESS: String = "io.kovanica.light.ADDRESS_BOOK_RESULT"
    }
}

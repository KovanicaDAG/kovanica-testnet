package io.kovanica.comms

import android.app.Activity
import android.app.ActivityManager
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.Drawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.os.Bundle
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.InputMethodManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import io.kovanica.chain.ChainIds
import org.json.JSONObject
import uniffi.kovanica_light.createWallet
import uniffi.kovanica_light.importWallet
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors
import kotlin.math.roundToInt

/**
 * Sealed 1:1 messages over the user's own relay. Everything here is client-only: the
 * keystore is decrypted on this device, envelopes are sealed with the phone's key, and
 * the relay only ever stores ciphertext. Crypto and HTTP run on one background thread
 * because Argon2id needs 64 MiB.
 *
 * This is the whole app. Create or import an identity on this phone, then seal 1:1
 * messages to a relay. Contacts are local. A name can be looked up read-only from an
 * on-chain registry. Nothing in the registry path signs, registers, or deploys anything.
 *
 * The screen is laid out programmatically on purpose — this app has no `res/`.
 */
class MessagesActivity : Activity() {
    private val io = Executors.newSingleThreadExecutor()
    private val stamps = SimpleDateFormat("d MMM · HH:mm", Locale.getDefault())

    private lateinit var store: CommsStore
    private lateinit var status: TextView
    private lateinit var scroll: ScrollView
    private lateinit var composeCard: LinearLayout
    private lateinit var commsIdValue: TextView
    private lateinit var pubkeyValue: TextView
    private lateinit var relayField: EditText
    private lateinit var rpcField: EditText
    private lateinit var passField: EditText
    private lateinit var mnemonicField: EditText
    private lateinit var recipientField: EditText
    private lateinit var messageField: EditText
    private lateinit var inbox: LinearLayout

    // Contacts. The registry field, lookup result and manual-add fields all live inside
    // the collapsible "Add" form so the list stays the visible part of the card.
    private lateinit var registryState: TextView
    private lateinit var registryField: EditText
    private lateinit var contactList: LinearLayout
    private lateinit var addForm: LinearLayout
    private lateinit var addToggle: Button
    private lateinit var lookupNameField: EditText
    private lateinit var resolvedBlock: LinearLayout
    private lateinit var manualPubkeyField: EditText
    private lateinit var manualLabelField: EditText

    /** Last successful name lookup, waiting for the user to confirm it with "Add". */
    private var resolved: RegistryEntry? = null
    private var resolvedName: String = ""

    /** Pubkey of the row that is showing the inline remove confirmation, if any. */
    private var pendingRemoval: String? = null

    /** Set once the keystore is unlocked; null until then. */
    private var client: CommsClient? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Make the system chrome part of the surface instead of fighting it.
        actionBar?.hide()
        window.setBackgroundDrawable(ColorDrawable(INK))
        window.statusBarColor = INK

        store = CommsStore(this)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(24), dp(20), dp(36))
            setBackgroundColor(INK)
        }

        root.addStack(header())
        root.addView(rule(), LinearLayout.LayoutParams(dp(40), dp(3)).apply { topMargin = dp(14) })

        status = TextView(this).apply {
            textSize = 13f
            setLineSpacing(0f, 1.3f)
            setPadding(dp(14), dp(12), dp(14), dp(12))
        }
        root.addStack(status, 18)
        setStatus("Enter your passphrase and unlock to load your identity.", Tone.NEUTRAL)

        relayField = field(CommsStore.DEFAULT_RELAY_URL, store.relayUrl)
        rpcField = field(
            "Node RPC for name lookup",
            prefs().getString(KEY_RPC, DEFAULT_RPC) ?: DEFAULT_RPC,
        )
        mnemonicField = field("24-word seed, only when importing")
        commsIdValue = monoValue("Unlock to reveal")
        commsIdValue.setTextColor(MUTED)
        pubkeyValue = monoValue("Unlock to reveal")
        pubkeyValue.setTextColor(MUTED)
        passField = field("Passphrase").apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        recipientField = field("Recipient public key (hex)").apply {
            typeface = Typeface.MONOSPACE
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        messageField = field("Write your message").apply {
            setSingleLine(false)
            inputType = InputType.TYPE_CLASS_TEXT or
                InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
            gravity = Gravity.TOP or Gravity.START
            minLines = 3
            maxLines = 8
        }
        registryField = field("Registry contract address", store.registryContract).apply {
            typeface = Typeface.MONOSPACE
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        lookupNameField = field("Name to look up, e.g. alice").apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        manualPubkeyField = field("Public key (64 hex)").apply {
            typeface = Typeface.MONOSPACE
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        manualLabelField = field("Label, e.g. Bob")

        val identity = card().apply {
            addStack(sectionLabel("Identity"))
            addStack(labelled("Comms id", commsIdValue), 2)
            addStack(labelled("Wallet public key", pubkeyValue), 14)
        }
        root.addStack(identity, 18)

        val relay = card().apply {
            addStack(sectionLabel("Relay"))
            addStack(relayField, 2)
            addStack(rpcField, 10)
        }
        root.addStack(relay, 18)

        val setup = card().apply {
            addStack(sectionLabel("This phone"))
            addStack(
                caption("Create an identity, or import the 24 words from another Kovanica app. The seed stays here."),
                0,
            )
            addStack(mnemonicField, 8)
            addStack(button("Create identity") { onCreateIdentity() }, 12)
            addStack(button("Import identity", filled = false) { onImportIdentity() }, 10)
        }
        root.addStack(setup, 18)

        val unlock = card().apply {
            addStack(sectionLabel("Keystore"))
            addStack(passField, 2)
            addStack(button("Unlock") { unlock() }, 12)
        }
        root.addStack(unlock, 18)

        registryState = TextView(this).apply {
            textSize = 12f
            setLineSpacing(0f, 1.3f)
            setTextColor(MUTED)
        }
        val contactsCard = card().apply {
            addStack(contactsHeader())
            addStack(registryState, 4)
            contactList = LinearLayout(this@MessagesActivity).apply {
                orientation = LinearLayout.VERTICAL
            }
            addStack(contactList, 12)
            addForm = addFormView()
            addStack(addForm, 14)
        }
        root.addStack(contactsCard, 18)
        registryField.addTextChangedListener(registryWatcher())
        updateRegistryState()
        renderContacts()

        composeCard = card().apply {
            addStack(sectionLabel("New message"))
            addStack(recipientField, 2)
            addStack(messageField, 10)
            addStack(button("Send") { send() }, 12)
        }
        root.addStack(composeCard, 18)

        inbox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val inboxCard = card().apply {
            addStack(inboxHeader())
            addStack(inbox, 12)
        }
        root.addStack(inboxCard, 18)
        renderInbox(emptyList())

        setContentView(ScrollView(this).apply {
            isFillViewport = true
            setBackgroundColor(INK)
            addView(root)
        }.also { scroll = it })
    }

    override fun onDestroy() {
        io.shutdown()
        super.onDestroy()
    }

    override fun onStop() {
        super.onStop()
        if (isChangingConfigurations) return
        window.decorView.post {
            if (isDestroyed || isChangingConfigurations) return@post
            if (!processInForeground()) lock()
        }
    }

    /** True while any screen of this app is still in front of the user. */
    private fun processInForeground(): Boolean {
        val manager = getSystemService(ACTIVITY_SERVICE) as ActivityManager
        val processes = manager.runningAppProcesses ?: return false
        val pid = android.os.Process.myPid()
        return processes.any {
            it.pid == pid &&
                it.importance <= ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND
        }
    }

    /** Forget the unlocked key and the typed passphrase when the app leaves the screen. */
    private fun lock() {
        client = null
        if (::passField.isInitialized) passField.setText("")
        if (::mnemonicField.isInitialized) mnemonicField.setText("")
        if (::commsIdValue.isInitialized) {
            commsIdValue.text = "Unlock to reveal"
            commsIdValue.setTextColor(MUTED)
        }
        if (::pubkeyValue.isInitialized) {
            pubkeyValue.text = "Unlock to reveal"
            pubkeyValue.setTextColor(MUTED)
        }
    }

    // --- actions -------------------------------------------------------------------------

    private fun unlock() {
        val relay = relayField.text.toString().trim()
        val passphrase = passField.text.toString()
        if (relay.isEmpty()) {
            setStatus("Enter the relay address, like http://10.0.2.2:8787.", Tone.ERROR)
            return
        }
        saveRelay(relay)
        saveRpc(rpcField.text.toString().trim())
        task("Unlocking your keystore…", work = {
            val keystore = keystore()
            val relayClient = RelayClient(relay)
            val comms = CommsClient(keystore, passphrase, relayClient)
            val pubkey = comms.myPubkeyHex()
            val commsId = comms.myCommsId()
            val relayOk = try {
                relayClient.health()
            } catch (_: Exception) {
                false
            }
            Unlocked(comms, pubkey, commsId, relayOk)
        }) { unlocked ->
            client = unlocked.comms
            showIdentity(unlocked.pubkey, unlocked.commsId)
            val note = if (unlocked.relayOk) {
                "Relay reachable."
            } else {
                "Relay not reachable — you can still unlock, but sending and refreshing need it."
            }
            setStatus("Unlocked.\n$note", if (unlocked.relayOk) Tone.OK else Tone.WARN)
        }
    }

    private fun onCreateIdentity() {
        val passphrase = passField.text.toString()
        if (passphrase.isEmpty()) {
            setStatus("Type a passphrase in the keystore card first.", Tone.ERROR)
            return
        }
        task("Creating an identity — this takes a few seconds…", work = {
            val created = createWallet(passphrase)
            prefs().edit().putString("keystore", created.keystoreJson).apply()
            "Identity created.\naddress ${created.address}\n" +
                "seed words (shown once, write them down):\n${created.mnemonic}"
        }) { line ->
            setStatus(line, Tone.OK)
        }
    }

    private fun onImportIdentity() {
        val passphrase = passField.text.toString()
        val seed = mnemonicField.text.toString().trim()
        if (passphrase.isEmpty()) {
            setStatus("Type a passphrase in the keystore card first.", Tone.ERROR)
            return
        }
        if (seed.isEmpty()) {
            setStatus("Paste the 24-word seed before importing.", Tone.ERROR)
            return
        }
        task("Importing identity…", work = {
            val imported = importWallet(seed, passphrase)
            prefs().edit().putString("keystore", imported.keystoreJson).apply()
            "Identity imported.\naddress ${imported.address}"
        }) { line ->
            mnemonicField.setText("")
            setStatus(line, Tone.OK)
        }
    }

    private fun send() {
        val recipient = recipientField.text.toString().trim()
        val body = messageField.text.toString().trim()
        val comms = client
        if (comms == null) {
            setStatus("Unlock first, so your key is available to seal the message.", Tone.ERROR)
            return
        }
        if (recipient.isEmpty()) {
            setStatus("Enter the recipient's public key (64 hex characters).", Tone.ERROR)
            return
        }
        if (body.isEmpty()) {
            setStatus("Type a message before sending.", Tone.ERROR)
            return
        }
        task("Sealing and sending…", work = {
            comms.sendEnvelope(recipient, body)
        }) { id ->
            messageField.setText("")
            setStatus("Sent. Envelope ${shortId(id)} is waiting on the relay.", Tone.OK)
        }
    }

    private fun refreshInbox() {
        val comms = client
        if (comms == null) {
            setStatus("Unlock first to load your inbox.", Tone.ERROR)
            return
        }
        saveRelay(relayField.text.toString().trim())
        task("Refreshing inbox…", work = {
            val messages = comms.fetchInbox()
            if (messages.isNotEmpty()) {
                comms.ackMessages(messages.map { it.envelopeId })
            }
            messages
        }) { messages ->
            renderInbox(messages)
            val line = when (messages.size) {
                0 -> "Inbox is empty."
                1 -> "Received 1 message."
                else -> "Received ${messages.size} messages."
            }
            setStatus(line, Tone.OK)
        }
    }

    // --- contacts ------------------------------------------------------------------------

    /** Load a contact into the compose field and bring that card into view. */
    private fun useContact(contact: Contact) {
        val pubkey = contact.pubkeyHex
        recipientField.setText(pubkey)
        recipientField.setSelection(pubkey.length)
        recipientField.requestFocus()
        val input = getSystemService(INPUT_METHOD_SERVICE) as? InputMethodManager
        scroll.post {
            scroll.smoothScrollTo(0, maxOf(0, composeCard.top - dp(12)))
            input?.showSoftInput(recipientField, InputMethodManager.SHOW_IMPLICIT)
        }
        val shown = contact.label.ifBlank { shortId(pubkey) }
        setStatus("Recipient set to $shown. Write your message, then Send.", Tone.NEUTRAL)
    }

    /** Read-only name lookup against the configured registry contract. */
    private fun lookUpName() {
        val name = lookupNameField.text.toString().trim().lowercase(Locale.US)
        val registry = registryField.text.toString().trim()
        persistRegistry(registry)
        validateName(name)?.let {
            setStatus(it, Tone.ERROR)
            return
        }
        if (registry.isEmpty()) {
            setStatus(
                "Name lookup needs a registry contract address. Paste it above, or add the contact by public key below.",
                Tone.WARN,
            )
            return
        }
        val registryCanonical = registryCanonical(registry)
        if (registryCanonical == null) {
            setStatus(
                "That registry address isn't valid on this chain. Use the 64-character kvnc…dag form.",
                Tone.ERROR,
            )
            return
        }
        val rpc = rpcField.text.toString().trim().ifEmpty { DEFAULT_RPC }
        saveRpc(rpc)
        task("Looking up \"$name\"…", work = {
            try {
                LookupOutcome(RegistryClient(NodeClient(rpc), registryCanonical).resolve(name), null)
            } catch (invalid: IllegalArgumentException) {
                // resolve() rejects names that break the registry rules; say so plainly.
                LookupOutcome(null, invalid.message ?: "That name isn't valid for this registry.")
            } catch (exception: Exception) {
                LookupOutcome(
                    null,
                    "Lookup failed — ${exception.message ?: "the node didn't answer"}",
                )
            }
        }) { outcome ->
            val error = outcome.error
            val entry = outcome.entry
            when {
                error != null -> setStatus(error, Tone.ERROR)
                entry == null -> setStatus(
                    "No entry for \"$name\" on that registry. Check the spelling, or add the contact by public key below.",
                    Tone.WARN,
                )
                else -> showResolved(name, entry)
            }
        }
    }

    /** Save the entry the user just looked up. */
    private fun addResolved() {
        val entry = resolved
        if (entry == null) {
            setStatus("Look up a name first.", Tone.WARN)
            return
        }
        val name = resolvedName
        val existing = store.label(entry.pubkeyHex)
        store.upsertContact(
            Contact(
                pubkeyHex = entry.pubkeyHex,
                label = name,
                name = name,
                relayEndpoints = entry.relayEndpoints,
            ),
        )
        resolved = null
        resolvedBlock.visibility = View.GONE
        lookupNameField.setText("")
        pendingRemoval = null
        setAddFormVisible(false)
        renderContacts()
        setStatus(savedLine(existing, name), Tone.OK)
    }

    /** Save a contact straight from a raw public key, no registry needed. */
    private fun addManual() {
        val pubkey = normalizePubkey(manualPubkeyField.text.toString())
        val label = manualLabelField.text.toString().trim()
        if (pubkey.isEmpty()) {
            setStatus("Enter the contact's public key (64 hex characters).", Tone.ERROR)
            return
        }
        if (!PUBKEY_PATTERN.matches(pubkey)) {
            setStatus("That doesn't look like a public key — it should be 64 hex characters.", Tone.ERROR)
            return
        }
        if (label.isEmpty()) {
            setStatus("Give the contact a label so you recognise them.", Tone.ERROR)
            return
        }
        val existing = store.label(pubkey)
        store.upsertContact(Contact(pubkeyHex = pubkey, label = label, name = null, relayEndpoints = null))
        manualPubkeyField.setText("")
        manualLabelField.setText("")
        pendingRemoval = null
        setAddFormVisible(false)
        renderContacts()
        setStatus(savedLine(existing, label), Tone.OK)
    }

    private fun removeContact(contact: Contact) {
        store.removeContact(contact.pubkeyHex)
        pendingRemoval = null
        renderContacts()
        setStatus("Removed ${contact.label.ifBlank { "contact" }}.", Tone.NEUTRAL)
    }

    private fun savedLine(existing: String?, label: String): String =
        if (existing == null) "Saved \"$label\". Tap the contact to message them." else "Updated \"$label\"."

    /** Mirrors the node-side name rules so an obviously bad name never leaves the phone. */
    private fun validateName(name: String): String? {
        if (name.isEmpty()) return "Type a name to look up, like \"alice\"."
        if (!NAME_PATTERN.matches(name)) return "Names use lowercase letters, digits and dashes only."
        if (name.startsWith("-") || name.endsWith("-")) return "Names can't start or end with a dash."
        if (name.contains("--")) return "Names can't have two dashes in a row."
        val bytes = name.toByteArray(Charsets.UTF_8).size
        if (bytes < 3 || bytes > 32) return "Names are between 3 and 32 characters long."
        return null
    }

    private fun toggleAddForm() {
        setAddFormVisible(addForm.visibility != View.VISIBLE)
    }

    private fun setAddFormVisible(visible: Boolean) {
        addForm.visibility = if (visible) View.VISIBLE else View.GONE
        addToggle.text = if (visible) "Done" else "Add"
        if (!visible) {
            resolved = null
            resolvedBlock.visibility = View.GONE
        }
    }

    private fun persistRegistry(value: String) {
        if (store.registryContract != value) {
            store.setRegistryContract(value)
        }
    }

    /**
     * Chain id from the shared `chainId` pref, when the wallet has set one.
     * Absent means base32 only: this app has no chain picker, and guessing
     * 1337 would turn a legacy hex address into canonical on every chain.
     */
    private fun addressChain(): Long =
        prefs().getString("chainId", null)?.trim()?.toLongOrNull() ?: ChainIds.UNSPECIFIED

    /** Canonical registry address, or null when [raw] is not valid for [addressChain]. */
    private fun registryCanonical(raw: String): String? {
        val key = KvncAddress.normalizeHex(raw, addressChain()) ?: return null
        return KvncAddress.display(key)
    }

    /** Keep the always-visible state line honest as the address is typed. */
    private fun updateRegistryState() {
        val value = registryField.text.toString().trim()
        if (value.isEmpty()) {
            registryState.text =
                "Name lookup is off — no registry contract address set. Tap Add to save someone by public key."
            registryState.setTextColor(MUTED)
        } else if (registryCanonical(value) == null) {
            registryState.text = "That isn't a Kovanica address on this chain."
            registryState.setTextColor(BAD)
        } else {
            registryState.text = "Name lookup on · ${KvncAddress.short(value)}"
            registryState.setTextColor(ACCENT)
        }
    }

    // --- rendering -----------------------------------------------------------------------

    private fun showIdentity(pubkey: String, commsId: String) {
        commsIdValue.apply {
            text = commsId
            setTextColor(TEXT)
        }
        pubkeyValue.apply {
            text = pubkey
            setTextColor(TEXT)
        }
    }

    private fun renderInbox(messages: List<ReceivedMessage>) {
        inbox.removeAllViews()
        if (messages.isEmpty()) {
            inbox.addStack(TextView(this).apply {
                text = "Nothing here yet. Messages sent to you appear after Refresh."
                setTextColor(MUTED)
                textSize = 13f
                setLineSpacing(0f, 1.25f)
            })
            return
        }
        messages.forEachIndexed { index, message ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                background = rounded(SURFACE_2, 14, LINE, 1)
                setPadding(dp(14), dp(12), dp(14), dp(12))
            }
            val meta = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            meta.addView(TextView(this).apply {
                text = shortId(message.senderCommsId)
                contentDescription = message.senderCommsId
                setTextColor(ACCENT)
                typeface = Typeface.MONOSPACE
                textSize = 12f
            }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            meta.addView(TextView(this).apply {
                text = stamp(message.sentAtMs)
                setTextColor(MUTED)
                textSize = 11f
            })
            row.addView(meta)
            row.addView(TextView(this).apply {
                text = bodyOf(message.payloadJson)
                setTextColor(TEXT)
                textSize = 15f
                setLineSpacing(0f, 1.25f)
                setPadding(0, dp(8), 0, 0)
            })
            inbox.addStack(row, if (index == 0) 0 else 8)
        }
    }

    private fun renderContacts() {
        contactList.removeAllViews()
        val people = store.contacts()
        if (people.isEmpty()) {
            contactList.addStack(TextView(this).apply {
                text = "No contacts yet. Tap Add to keep someone by name or public key."
                setTextColor(MUTED)
                textSize = 13f
                setLineSpacing(0f, 1.25f)
            })
            return
        }
        people
            .sortedBy { it.label.lowercase(Locale.US) }
            .forEachIndexed { index, contact ->
                contactList.addStack(contactRow(contact), if (index == 0) 0 else 8)
            }
    }

    private fun contactRow(contact: Contact): LinearLayout {
        val key = normalizePubkey(contact.pubkeyHex)
        if (key == pendingRemoval) {
            return removalRow(contact)
        }
        val label = contact.label.ifBlank { shortId(contact.pubkeyHex) }
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = ripple(SURFACE_2, 14)
            setPadding(dp(14), dp(12), dp(12), dp(12))
            isClickable = true
            isFocusable = true
            setOnClickListener { useContact(contact) }
            setOnLongClickListener {
                pendingRemoval = key
                renderContacts()
                true
            }

            val top = LinearLayout(this@MessagesActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            top.addView(
                TextView(this@MessagesActivity).apply {
                    text = label
                    setTextColor(TEXT)
                    textSize = 15f
                    typeface = Typeface.DEFAULT_BOLD
                },
                LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
            )
            // The handle only earns its place when it says something the label doesn't.
            val handle = contact.name
            if (!handle.isNullOrBlank() && handle != contact.label) {
                top.addView(TextView(this@MessagesActivity).apply {
                    text = "@$handle"
                    setTextColor(ACCENT)
                    typeface = Typeface.MONOSPACE
                    textSize = 12f
                    setPadding(dp(8), 0, dp(8), 0)
                })
            }
            top.addView(TextView(this@MessagesActivity).apply {
                text = "›"
                setTextColor(MUTED)
                textSize = 16f
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            })
            addView(top)

            addView(TextView(this@MessagesActivity).apply {
                text = shortId(contact.pubkeyHex)
                contentDescription = contact.pubkeyHex
                setTextColor(MUTED)
                typeface = Typeface.MONOSPACE
                textSize = 12f
                setPadding(0, dp(4), 0, 0)
            })
        }
    }

    private fun removalRow(contact: Contact): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = rounded(SURFACE_2, 14, BAD, 1)
        setPadding(dp(14), dp(12), dp(14), dp(12))
        isClickable = true // swallow taps; only the two buttons act

        addView(TextView(this@MessagesActivity).apply {
            text = "Remove ${contact.label.ifBlank { shortId(contact.pubkeyHex) }}?"
            setTextColor(TEXT)
            textSize = 14f
        })
        val actions = LinearLayout(this@MessagesActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(10), 0, 0)
        }
        actions.addView(
            button("Remove", filled = false) { removeContact(contact) }.apply {
                setTextColor(BAD)
            },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
        )
        actions.addView(
            button("Keep", filled = false) {
                pendingRemoval = null
                renderContacts()
            },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                leftMargin = dp(10)
            },
        )
        addView(actions)
    }

    private fun showResolved(name: String, entry: RegistryEntry) {
        resolved = entry
        resolvedName = name
        resolvedBlock.removeAllViews()
        resolvedBlock.addStack(TextView(this).apply {
            text = "RESOLVED"
            setTextColor(ACCENT)
            textSize = 11f
            letterSpacing = 0.18f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 0, dp(10))
        })
        resolvedBlock.addStack(labelled("Name", monoValue("@$name")))
        resolvedBlock.addStack(labelled("Public key", monoValue(entry.pubkeyHex)), 10)
        resolvedBlock.addStack(labelled("Relay endpoints", endpointsView(entry.relayEndpoints)), 10)
        resolvedBlock.addStack(button("Add \"$name\"") { addResolved() }, 12)
        resolvedBlock.visibility = View.VISIBLE
        setStatus("Found \"$name\". Check the key, then Add.", Tone.NEUTRAL)
    }

    private fun endpointsView(endpoints: List<String>): TextView = TextView(this).apply {
        if (endpoints.isEmpty()) {
            text = "None listed. Messages will use your own relay."
            setTextColor(MUTED)
            typeface = Typeface.DEFAULT
            setTextIsSelectable(false)
        } else {
            text = endpoints.joinToString("\n")
            setTextColor(TEXT)
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
        }
        textSize = 12f
        setLineSpacing(0f, 1.3f)
    }

    private fun bodyOf(payloadJson: String): String = try {
        JSONObject(payloadJson).optString("body").ifEmpty { payloadJson }
    } catch (_: Exception) {
        payloadJson
    }

    private fun stamp(sentAtMs: Long): String = stamps.format(Date(sentAtMs))

    private fun shortId(value: String): String =
        if (value.length > 16) "${value.take(8)}…${value.takeLast(6)}" else value

    /** Match how `CommsStore` keys contacts: trimmed, lowercase, no `0x`. */
    private fun normalizePubkey(raw: String): String =
        raw.trim().removePrefix("0x").removePrefix("0X").lowercase(Locale.US)

    // --- status --------------------------------------------------------------------------

    private enum class Tone { NEUTRAL, OK, WARN, ERROR }

    private fun setStatus(text: String, tone: Tone) {
        status.text = text
        val (foreground, background) = when (tone) {
            Tone.NEUTRAL -> MUTED to SURFACE
            Tone.OK -> GOOD to GOOD_BG
            Tone.WARN -> ACCENT to ACCENT_BG
            Tone.ERROR -> BAD to BAD_BG
        }
        status.setTextColor(foreground)
        status.background = rounded(background, 14, LINE, 1)
    }

    // --- background helper ---------------------------------------------------------------

    private fun <T> task(start: String, work: () -> T, done: (T) -> Unit) {
        setStatus(start, Tone.NEUTRAL)
        io.execute {
            val outcome = try {
                Result.success(work())
            } catch (exception: Exception) {
                Result.failure(exception)
            }
            runOnUiThread {
                outcome.fold(
                    onSuccess = done,
                    onFailure = { setStatus(it.message ?: it.toString(), Tone.ERROR) },
                )
            }
        }
    }

    // --- widgets -------------------------------------------------------------------------

    private fun header(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(TextView(this@MessagesActivity).apply {
            text = "Kovanica · COMMS"
            setTextColor(ACCENT)
            textSize = 11f
            letterSpacing = 0.22f
            typeface = Typeface.DEFAULT_BOLD
        })
        addView(TextView(this@MessagesActivity).apply {
            text = "Comms"
            setTextColor(TEXT)
            textSize = 30f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, dp(6), 0, 0)
        })
        addView(TextView(this@MessagesActivity).apply {
            text = "Sealed 1:1 messages. The identity stays on this phone."
            setTextColor(MUTED)
            textSize = 13f
            setLineSpacing(0f, 1.3f)
            setPadding(0, dp(8), 0, 0)
        })
    }

    private fun rule(): View = View(this).apply { background = rounded(ACCENT, 2) }

    private fun card(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = rounded(SURFACE, 18, LINE, 1)
        setPadding(dp(16), dp(16), dp(16), dp(16))
    }

    private fun inboxHeader(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        addView(
            sectionLabel("Inbox", bottomPadDp = 0),
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
        )
        addView(
            button("Refresh", filled = false) { refreshInbox() },
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ),
        )
    }

    private fun contactsHeader(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        addView(
            sectionLabel("Contacts", bottomPadDp = 0),
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
        )
        addToggle = button("Add", filled = false) { toggleAddForm() }
        addView(
            addToggle,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ),
        )
    }

    private fun addFormView(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        visibility = View.GONE

        addStack(caption("Look up a registered name"))
        addStack(registryField, 8)
        addStack(nameRow(), 10)

        resolvedBlock = LinearLayout(this@MessagesActivity).apply {
            orientation = LinearLayout.VERTICAL
            background = rounded(SURFACE_2, 14, LINE, 1)
            setPadding(dp(14), dp(12), dp(14), dp(12))
            visibility = View.GONE
        }
        addStack(resolvedBlock, 12)

        addHairline(18, 18)

        addStack(caption("Or add by public key"))
        addStack(manualPubkeyField, 8)
        addStack(manualLabelField, 8)
        addStack(button("Add by public key", filled = false) { addManual() }, 12)
    }

    private fun nameRow(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        addView(
            lookupNameField,
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
        )
        addView(
            button("Look up", filled = false) { lookUpName() },
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { leftMargin = dp(10) },
        )
    }

    private fun caption(text: String): TextView = TextView(this).apply {
        this.text = text
        setTextColor(MUTED)
        textSize = 12f
    }

    /** Amber press feedback for the contact rows, clipped to the rounded card. */
    private fun ripple(fill: Int, radiusDp: Int): Drawable = RippleDrawable(
        ColorStateList.valueOf(RIPPLE),
        rounded(fill, radiusDp, LINE, 1),
        null,
    )

    private fun labelled(caption: String, value: TextView): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(TextView(this@MessagesActivity).apply {
            text = caption
            setTextColor(MUTED)
            textSize = 12f
            setPadding(0, 0, 0, dp(4))
        })
        addStack(value)
    }

    private fun sectionLabel(caption: String, bottomPadDp: Int = 10): TextView = TextView(this).apply {
        text = caption.uppercase(Locale.US)
        setTextColor(MUTED)
        textSize = 11f
        letterSpacing = 0.18f
        typeface = Typeface.DEFAULT_BOLD
        setPadding(0, 0, 0, dp(bottomPadDp))
    }

    private fun monoValue(text: String): TextView = TextView(this).apply {
        this.text = text
        setTextColor(TEXT)
        typeface = Typeface.MONOSPACE
        textSize = 13f
        setTextIsSelectable(true)
        setLineSpacing(0f, 1.2f)
    }

    private fun field(hint: String, value: String = ""): EditText = EditText(this).apply {
        this.hint = hint
        setText(value)
        setTextColor(TEXT)
        setHintTextColor(MUTED)
        textSize = 15f
        background = rounded(SURFACE_2, 12, LINE, 1)
        setPadding(dp(14), dp(13), dp(14), dp(13))
        inputType = InputType.TYPE_CLASS_TEXT
        maxLines = 1
    }

    private fun button(caption: String, filled: Boolean = true, action: () -> Unit): Button =
        Button(this).apply {
            text = caption
            isAllCaps = false
            textSize = 15f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(if (filled) ACCENT_INK else ACCENT)
            background = if (filled) rounded(ACCENT, 12) else rounded(SURFACE_2, 12, LINE, 1)
            setPadding(dp(18), dp(12), dp(18), dp(12))
            minHeight = dp(48)
            stateListAnimator = null
            setOnClickListener { action() }
        }

    private fun rounded(fill: Int, radiusDp: Int, stroke: Int? = null, strokeDp: Int = 1): GradientDrawable =
        GradientDrawable().apply {
            setColor(fill)
            cornerRadius = dp(radiusDp).toFloat()
            if (stroke != null) setStroke(dp(strokeDp), stroke)
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

    /** A one-pixel separator with breathing room above and below. */
    private fun ViewGroup.addHairline(top: Int, bottom: Int) {
        addView(
            View(this@MessagesActivity).apply { background = rounded(LINE, 1) },
            LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(1)).apply {
                topMargin = dp(top)
                bottomMargin = dp(bottom)
            },
        )
    }

    // --- io helpers ----------------------------------------------------------------------

    /** Persist the registry address as it is typed and keep the state line in step. */
    private fun registryWatcher(): TextWatcher = object : TextWatcher {
        override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
        override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
        override fun afterTextChanged(s: Editable?) {
            updateRegistryState()
            persistRegistry(registryField.text.toString().trim())
        }
    }

    private fun saveRelay(relay: String) {
        store.relayUrl = relay
    }

    private fun saveRpc(rpc: String) {
        val value = rpc.ifEmpty { DEFAULT_RPC }
        prefs().edit().putString(KEY_RPC, value).apply()
    }

    private fun prefs() = getSharedPreferences("kvnc", MODE_PRIVATE)

    private fun keystore(): String =
        prefs().getString("keystore", null) ?: error("Create or import a wallet first.")

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).roundToInt()

    private data class Unlocked(
        val comms: CommsClient,
        val pubkey: String,
        val commsId: String,
        val relayOk: Boolean,
    )

    /** Either a resolved registry entry or a plain sentence for the status banner. */
    private data class LookupOutcome(val entry: RegistryEntry?, val error: String?)

    companion object {
        // Ink-toned surface. Explicit so the screen reads the same on any device theme.
        private val INK = 0xFF0E1116.toInt()
        private val SURFACE = 0xFF171C23.toInt()
        private val SURFACE_2 = 0xFF1E242C.toInt()
        private val LINE = 0xFF2A323C.toInt()
        private val TEXT = 0xFFEDF1F6.toInt()
        private val MUTED = 0xFF95A0AE.toInt()
        private val ACCENT = 0xFFF0B429.toInt()
        private val ACCENT_INK = 0xFF1A1E25.toInt()
        private val ACCENT_BG = 0x1AF0B429.toInt()
        private val GOOD = 0xFF5BD6A0.toInt()
        private val GOOD_BG = 0x1A5BD6A0.toInt()
        private val BAD = 0xFFFF7B84.toInt()
        private val BAD_BG = 0x1AFF7B84.toInt()

        /** Press tint for tappable contact rows: the accent at ~18% alpha. */
        private val RIPPLE = 0x2EF0B429.toInt()

        /** Node RPC address, set on the main screen under the same prefs key. */
        private const val KEY_RPC = "rpc"
        private const val DEFAULT_RPC = "http://10.0.2.2:8545"

        private val PUBKEY_PATTERN = Regex("^[0-9a-f]{64}$")
        private val NAME_PATTERN = Regex("^[a-z0-9-]+$")
    }
}

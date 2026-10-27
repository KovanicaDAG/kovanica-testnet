package io.kovanica.wallet

import android.app.Activity
import android.graphics.Typeface
import android.graphics.drawable.ColorDrawable
import android.os.Bundle
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONArray
import uniffi.kovanica_light.contractAddressForRaw
import uniffi.kovanica_light.signCallRaw
import uniffi.kovanica_light.signDeployRaw
import uniffi.kovanica_light.walletAddress
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.util.concurrent.Executors
import kotlin.math.roundToInt

/**
 * Create a KVP-102 token, end to end, from this phone.
 *
 * Creating a token is **two** transactions, in this order:
 *
 * 1. A `Deploy` that publishes the token contract. Its fee scales with the
 *    contract's bytecode, so it costs more than a plain KUNA send.
 * 2. A `Call` into `token_create` that mints the opening supply.
 *
 * The contract address is **derived here**, not returned by the node: it is a
 * pure function of the sender and the deploy's nonce
 * ([contractAddressForRaw]). The second transaction cannot land until the first
 * is mined — a call to a contract with no code fails — so this screen sends the
 * deploy, polls `kovanica_getCode` until the bytecode appears, and only then
 * sends the create call. The nonce for the call is the deploy's nonce + 1.
 *
 * The passphrase is read on the UI thread and only reaches the signer here; the
 * node never sees it. Every failure lands in the status banner, never a crash.
 *
 * Laid out programmatically — this app has no `res/` and no Compose.
 */
class CreateTokenActivity : Activity() {
    private val io = Executors.newSingleThreadExecutor()

    private lateinit var status: TextView
    private lateinit var nameField: EditText
    private lateinit var symbolField: EditText
    private lateinit var decimalsField: EditText
    private lateinit var supplyField: EditText
    private lateinit var passField: EditText
    private lateinit var validation: TextView
    private lateinit var createButton: Button
    private lateinit var resultCard: LinearLayout
    private lateinit var contractText: TextView
    private lateinit var resultMeta: TextView

    private var busy = false

    /** Set once the screen is going away, so late background work stops touching the view. */
    @Volatile
    private var gone = false

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
        }

        root.addView(header())
        root.addView(
            View(this).apply {
                background = WalletUi.rounded(this@CreateTokenActivity, WalletUi.ACCENT, 2)
            },
            LinearLayout.LayoutParams(dp(40), dp(3)).apply { topMargin = dp(14) },
        )
        root.addStack(status, 18)

        resultCard = resultCardView()
        root.addStack(resultCard, 18)
        root.addStack(detailsCard(), 18)
        root.addStack(unlockCard(), 18)
        root.addStack(noteCard(), 18)

        createButton = WalletUi.button(this, "Create token") { createToken() }
        root.addStack(createButton, 18)
        root.addStack(WalletUi.button(this, "Back to wallet", filled = false) { finish() }, 10)

        setContentView(ScrollView(this).apply {
            isFillViewport = true
            setBackgroundColor(WalletUi.INK)
            addView(root)
        })

        val hasWallet = keystoreOrNull() != null
        setStatus(
            if (hasWallet) {
                "Name your token, set how many you start with, then create it. This is two " +
                    "transactions."
            } else {
                "Create or import a wallet first — a token needs one to sign with."
            },
            if (hasWallet) Tone.NEUTRAL else Tone.WARN,
        )
        renderValidation()
    }

    override fun onStop() {
        super.onStop()
        // Don't keep the typed passphrase in the field once the screen is out of sight.
        if (::passField.isInitialized) passField.setText("")
    }

    override fun onDestroy() {
        gone = true
        io.shutdown()
        super.onDestroy()
    }

    // --- cards ---------------------------------------------------------------------------

    private fun detailsCard(): LinearLayout = WalletUi.card(this).apply {
        addStack(WalletUi.sectionLabel(this@CreateTokenActivity, "Token details"))

        nameField = WalletUi.field(this@CreateTokenActivity, "Name, e.g. Kovanica Gold")
        addStack(nameField, 2)
        symbolField = WalletUi.field(this@CreateTokenActivity, "Symbol, e.g. KGOLD")
        addStack(symbolField, 8)
        decimalsField = WalletUi.field(this@CreateTokenActivity, "Decimals (0–18)", "9", mono = true)
            .apply { inputType = InputType.TYPE_CLASS_NUMBER }
        addStack(decimalsField, 8)
        supplyField = WalletUi.field(
            this@CreateTokenActivity,
            "Initial supply, in whole tokens",
            "",
            mono = true,
        ).apply { inputType = InputType.TYPE_CLASS_NUMBER }
        addStack(supplyField, 8)

        validation = TextView(this@CreateTokenActivity).apply {
            textSize = 12f
            setLineSpacing(0f, 1.3f)
            visibility = View.GONE
        }
        addStack(validation, 10)

        addStack(
            WalletUi.caption(
                this@CreateTokenActivity,
                "Decimals only describe the fractional part; 9 matches KUNA. The supply is a " +
                    "whole number of tokens and is scaled by the decimals you pick.",
            ),
            12,
        )

        val watcher = object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) = renderValidation()
        }
        listOf(nameField, symbolField, decimalsField, supplyField).forEach {
            it.addTextChangedListener(watcher)
        }
    }

    private fun unlockCard(): LinearLayout = WalletUi.card(this).apply {
        addStack(WalletUi.sectionLabel(this@CreateTokenActivity, "Unlock"))
        passField = WalletUi.field(this@CreateTokenActivity, "Passphrase").apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        addStack(passField, 2)
        passField.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) = renderValidation()
        })
        addStack(
            WalletUi.caption(
                this@CreateTokenActivity,
                "Your passphrase unlocks the wallet so the two transactions can be signed. It " +
                    "stays on this phone and is never sent to the node.",
            ),
            12,
        )
    }

    private fun noteCard(): LinearLayout = WalletUi.card(this).apply {
        addStack(WalletUi.sectionLabel(this@CreateTokenActivity, "Before you create"))
        addStack(
            WalletUi.caption(
                this@CreateTokenActivity,
                "This takes two transactions: a deploy that publishes the contract, whose fee " +
                    "grows with the contract's size, then a call that creates the token and sets " +
                    "its opening supply. The deploy has to be mined before the call, so it can " +
                    "take a minute or two. The contract address is worked out on this phone — " +
                    "the node doesn't report it.",
            ),
            0,
        )
    }

    private fun resultCardView(): LinearLayout = WalletUi.card(this).apply {
        visibility = View.GONE
        addStack(WalletUi.sectionLabel(this@CreateTokenActivity, "Created"))
        contractText = WalletUi.mono(this@CreateTokenActivity, "", 13f)
        addStack(contractText, 0)
        resultMeta = TextView(this@CreateTokenActivity).apply {
            textSize = 11f
            setTextColor(WalletUi.MUTED)
            setLineSpacing(0f, 1.3f)
            setPadding(0, dp(8), 0, 0)
        }
        addStack(resultMeta, 0)
        addStack(
            WalletUi.caption(
                this@CreateTokenActivity,
                "That is the token's contract address. It's on your watchlist for this network " +
                    "now — go back to the wallet to see its balance.",
            ),
            10,
        )
    }

    // --- validation ----------------------------------------------------------------------

    /** The parsed, ready-to-sign inputs, or `null` with a message explaining what's missing. */
    private data class Input(
        val name: String,
        val symbol: String,
        val decimals: Int,
        val supplyAtoms: BigInteger,
    )

    /** A validation message and whether it is a hard format error (red) or just guidance. */
    private data class Problem(val message: String, val severe: Boolean)

    private fun parseInputs(): Pair<Input?, Problem?> {
        val name = nameField.text.toString().trim()
        if (name.isEmpty()) return null to Problem("Give the token a name.", severe = false)
        if (name.length > 64) {
            return null to Problem("Keep the name to 64 characters or fewer.", severe = true)
        }

        val symbol = symbolField.text.toString().trim()
        if (symbol.isEmpty()) {
            return null to Problem("Give the token a short symbol, like KGOLD.", severe = false)
        }
        if (symbol.any { it.isWhitespace() }) {
            return null to Problem("The symbol can't contain spaces.", severe = true)
        }
        if (symbol.length > 12) {
            return null to Problem("Keep the symbol to 12 characters or fewer, like KGOLD.", severe = true)
        }

        val decimals = decimalsField.text.toString().trim().toIntOrNull()
        if (decimals == null || decimals !in 0..18) {
            return null to Problem("Decimals must be a whole number from 0 to 18.", severe = true)
        }

        val supplyRaw = supplyField.text.toString().trim()
        if (supplyRaw.isEmpty()) {
            return null to Problem("Enter the starting supply, in whole tokens.", severe = false)
        }
        val supplyWhole = supplyRaw.toBigIntegerOrNull()
        if (supplyWhole == null) {
            return null to Problem(
                "Enter the starting supply as a whole number of tokens, like 1000000.",
                severe = true,
            )
        }
        if (supplyWhole.signum() <= 0) {
            return null to Problem("The starting supply has to be more than zero.", severe = true)
        }
        val atoms = supplyWhole * BigInteger.TEN.pow(decimals)
        if (atoms.bitLength() > 128) {
            return null to Problem("That starting supply is larger than a token can hold.", severe = true)
        }

        return Input(name, symbol, decimals, atoms) to null
    }

    private fun renderValidation() {
        if (!::validation.isInitialized) return
        val touched = nameField.text.isNotEmpty() ||
            symbolField.text.isNotEmpty() ||
            supplyField.text.isNotEmpty()
        if (!touched) {
            validation.visibility = View.GONE
            return
        }

        val (input, problem) = parseInputs()
        when {
            problem != null -> {
                validation.text = problem.message
                validation.setTextColor(if (problem.severe) WalletUi.BAD else WalletUi.MUTED)
            }
            passField.text.toString().isEmpty() -> {
                validation.text = "Enter the passphrase that unlocks your wallet."
                validation.setTextColor(WalletUi.MUTED)
            }
            else -> {
                val ready = input!!
                val supply = Amounts.format(ready.supplyAtoms, ready.decimals)
                validation.text = "Ready — creates ${ready.symbol} with a starting supply of $supply tokens."
                validation.setTextColor(WalletUi.GOOD)
            }
        }
        validation.visibility = View.VISIBLE
    }

    // --- the two transactions ------------------------------------------------------------

    private sealed interface Outcome {
        data class Done(
            val contractHex: String,
            val deployHash: String?,
            val callHash: String?,
        ) : Outcome

        data class Failed(val message: String) : Outcome
    }

    private fun createToken() {
        if (busy) return

        val keystore = keystoreOrNull()
        if (keystore == null) {
            setStatus("Create or import a wallet first — there's nothing to sign with.", Tone.WARN)
            return
        }
        val (input, problem) = parseInputs()
        if (input == null) {
            setStatus(problem!!.message, Tone.ERROR)
            return
        }
        val passphrase = passField.text.toString()
        if (passphrase.isEmpty()) {
            setStatus("Enter the passphrase that unlocks your wallet.", Tone.ERROR)
            return
        }

        // Everything below is read on the UI thread; the signer only ever sees it here.
        val rpc = NetworkPrefs.rpc(this)
        val chainId = NetworkPrefs.chainId(this).toULong()
        val networkId = NetworkPrefs.selectedId(this)

        setBusy(true)
        setStatus("Reading your wallet and the fee rate…", Tone.NEUTRAL)

        io.execute {
            val outcome = try {
                runCreate(
                    keystore = keystore,
                    passphrase = passphrase,
                    rpc = rpc,
                    chainId = chainId,
                    input = input,
                ) { line -> ui { setStatus(line, Tone.NEUTRAL) } }
            } catch (error: Exception) {
                Outcome.Failed(error.message ?: "The token couldn't be created.")
            }

            ui {
                setBusy(false)
                when (outcome) {
                    is Outcome.Done -> {
                        TokenStore(this).add(networkId, outcome.contractHex)
                        passField.setText("")
                        contractText.text = KvncAddress.display(outcome.contractHex)
                        resultMeta.text = buildString {
                            append("Deploy: ")
                            append(outcome.deployHash?.take(18) ?: "sent")
                            append("\nCreate call: ")
                            append(outcome.callHash?.take(18) ?: "sent")
                        }
                        resultCard.visibility = View.VISIBLE
                        setStatus("Token created and added to your watchlist.", Tone.OK)
                    }
                    is Outcome.Failed -> setStatus(outcome.message, Tone.ERROR)
                }
            }
        }
    }

    /**
     * The blocking half: deploy, wait for the code to land, then create. Never
     * touches the view directly — progress goes through [note] and the final
     * outcome is applied on the UI thread by the caller.
     */
    private fun runCreate(
        keystore: String,
        passphrase: String,
        rpc: String,
        chainId: ULong,
        input: Input,
        note: (String) -> Unit,
    ): Outcome {
        val node = NodeClient(rpc)

        val sender = walletAddress(keystore)
        val nonce = parseQuantity(node.call("kovanica_getNonce", JSONArray().put(sender)))
        val feeRate = parseQuantity(node.call("kovanica_estimateFee", JSONArray()))

        val wasm = assets.open(WASM_ASSET).use { it.readBytes() }
        val codeHex = TokenCodec.hex(wasm)

        // Tx 1 — Deploy. It publishes the contract bytecode; the fee scales with its size.
        val deploy = signDeployRaw(keystore, passphrase, chainId, codeHex, nonce, feeRate)
        val deployHash = node.call("kovanica_sendRawTransaction", JSONArray().put(deploy))?.toString()

        // The node does not return the new address, so derive it from sender + deploy nonce.
        val contractHex = contractAddressForRaw(sender, nonce, chainId)
        val contract = KvncAddress.canonical(contractHex)
            ?: return Outcome.Failed("The new token address could not be encoded.")

        note("Deploy sent${shortHash(deployHash)}. Waiting for it to be mined…")

        // A call before the code exists fails, so poll until the bytecode appears.
        var mined = false
        for (attempt in 1..DEPLOY_POLLS) {
            Thread.sleep(DEPLOY_POLL_MS)
            val code = node.call("kovanica_getCode", JSONArray().put(contract))
            val text = code?.toString()?.trim().orEmpty()
            if (text.isNotEmpty() && !text.equals("0x", ignoreCase = true)) {
                mined = true
                break
            }
            note("Still waiting for the deploy to be mined… ($attempt/$DEPLOY_POLLS)")
        }
        if (!mined) {
            return Outcome.Failed(
                "The deploy wasn't mined in time, so the token wasn't created. It may still be " +
                    "pending — check your token list in a minute before you retry.",
            )
        }

        note("Deploy mined. Sending the create call…")

        // Tx 2 — Call `token_create` with bincode `(name, symbol, decimals, initial_supply)`.
        val argsHex = tokenCreateArgsHex(input.name, input.symbol, input.decimals, input.supplyAtoms)
        val call = signCallRaw(
            keystore,
            passphrase,
            chainId,
            contract,
            0uL,
            CREATE_METHOD,
            argsHex,
            CREATE_GAS_LIMIT,
            nonce + 1uL,
            feeRate,
        )
        val callHash = node.call("kovanica_sendRawTransaction", JSONArray().put(call))?.toString()

        return Outcome.Done(contractHex, deployHash, callHash)
    }

    /**
     * The `token_create` calldata, exactly as `kovanica-execution` writes it:
     * bincode 1.3 with fixint + little-endian over
     * `(String name, String symbol, u8 decimals, u128 initial_supply)`.
     *
     * A `String` is a `u64` little-endian **byte** length then its UTF-8 bytes; a
     * `u8` is one byte; a `u128` is 16 little-endian bytes.
     */
    private fun tokenCreateArgsHex(
        name: String,
        symbol: String,
        decimals: Int,
        supplyAtoms: BigInteger,
    ): String {
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        val symbolBytes = symbol.toByteArray(Charsets.UTF_8)
        val out = ByteArrayOutputStream()
        out.write(u64le(nameBytes.size))
        out.write(nameBytes)
        out.write(u64le(symbolBytes.size))
        out.write(symbolBytes)
        out.write(decimals and 0xFF)
        out.write(u128le(supplyAtoms))
        return TokenCodec.hex(out.toByteArray())
    }

    /** A 64-bit little-endian integer, as bincode writes an `u64` length. */
    private fun u64le(value: Int): ByteArray {
        val out = ByteArray(8)
        val v = value.toLong()
        for (i in 0 until 8) out[i] = ((v ushr (8 * i)) and 0xFF).toByte()
        return out
    }

    /**
     * A `u128` as bincode writes it: 16 bytes, little-endian. The caller has
     * already checked the value fits and is positive, so any leading zero byte
     * `BigInteger.toByteArray` adds for the sign is simply dropped.
     */
    private fun u128le(value: BigInteger): ByteArray {
        val out = ByteArray(16)
        val be = value.toByteArray()
        val n = minOf(be.size, 16)
        for (i in 0 until n) out[i] = be[be.size - 1 - i]
        return out
    }

    private fun shortHash(hash: String?): String =
        if (hash.isNullOrBlank()) "" else " (tx ${hash.take(12)}…)"

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

    /** Dim the form and the button while the two transactions are in flight. */
    private fun setBusy(working: Boolean) {
        busy = working
        createButton.isEnabled = !working
        createButton.alpha = if (working) 0.5f else 1f
        createButton.text = if (working) "Creating…" else "Create token"
        listOf(nameField, symbolField, decimalsField, supplyField, passField).forEach {
            it.isEnabled = !working
        }
    }

    private fun ui(block: () -> Unit) {
        if (gone) return
        runOnUiThread { if (!gone) block() }
    }

    private fun keystoreOrNull(): String? =
        getSharedPreferences(NetworkPrefs.PREFS, MODE_PRIVATE).getString("keystore", null)

    private fun header(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(TextView(this@CreateTokenActivity).apply {
            text = "KVNC · NEW TOKEN"
            setTextColor(WalletUi.ACCENT)
            textSize = 11f
            letterSpacing = 0.22f
            typeface = Typeface.DEFAULT_BOLD
        })
        addView(TextView(this@CreateTokenActivity).apply {
            text = "Create a token"
            setTextColor(WalletUi.TEXT)
            textSize = 30f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, dp(6), 0, 0)
        })
        addView(TextView(this@CreateTokenActivity).apply {
            text = "Publish a KVP-102 token from this phone. Your keys never leave it."
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

    private companion object {
        /** Bundled KVP-102 token contract, shipped in `assets/`. */
        const val WASM_ASSET = "kovanica_token.wasm"

        /** The kovanica-token entry point that mints a token's opening supply. */
        const val CREATE_METHOD = "token_create"

        /**
         * Gas limit for the create call, in gas units: the node's `ExecutionConfig`
         * default (10_000_000). Creating a token writes the whole holder map, so
         * the call needs room; unused gas is not charged beyond the tx fee.
         */
        const val CREATE_GAS_LIMIT = 10_000_000uL

        /** How long to wait for the deploy to be mined before giving up. */
        const val DEPLOY_POLL_MS = 3_000L
        const val DEPLOY_POLLS = 30
    }
}

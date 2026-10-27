package io.kovanica.wallet

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Typeface
import android.graphics.drawable.ColorDrawable
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import kotlin.math.roundToInt

/**
 * The receive screen: show the wallet address in full, big and selectable, with
 * one-tap copy and a share sheet. Nothing here signs, decrypts a seed, or talks
 * to the network — the address is handed in by [MainActivity], which already
 * has it, so this screen works even when the node is unreachable.
 *
 * Laid out programmatically — this app has no `res/` and no Compose.
 */
class ReceiveActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var addressText: TextView
    private lateinit var address: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        actionBar?.hide()
        window.setBackgroundDrawable(ColorDrawable(WalletUi.INK))
        window.statusBarColor = WalletUi.INK

        address = intent.getStringExtra(EXTRA_ADDRESS).orEmpty()
        val network = intent.getStringExtra(EXTRA_NETWORK).orEmpty().ifEmpty { "this network" }

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
            View(this).apply { background = WalletUi.rounded(this@ReceiveActivity, WalletUi.ACCENT, 2) },
            LinearLayout.LayoutParams(dp(40), dp(3)).apply { topMargin = dp(14) },
        )

        if (address.isEmpty()) {
            setStatus("No wallet on this phone yet. Create or import one on the main screen.", Tone.WARN)
            root.addStack(status, 18)
            setContentView(ScrollView(this).apply {
                isFillViewport = true
                setBackgroundColor(WalletUi.INK)
                addView(root)
            })
            return
        }

        setStatus("Share this address to receive KUNA.", Tone.NEUTRAL)
        root.addStack(status, 18)

        val addressCard = WalletUi.card(this).apply {
            addStack(WalletUi.sectionLabel(this@ReceiveActivity, "Your address"))
            addressText = TextView(this@ReceiveActivity).apply {
                text = address
                setTextColor(WalletUi.TEXT)
                typeface = Typeface.MONOSPACE
                textSize = 16f
                setLineSpacing(dp(6).toFloat(), 1.25f)
                setTextIsSelectable(true)
                background = WalletUi.rounded(this@ReceiveActivity, WalletUi.SURFACE_2, 14, WalletUi.LINE, 1)
                setPadding(dp(16), dp(16), dp(16), dp(16))
                contentDescription = address
            }
            addStack(addressText, 2)
            addStack(qrBlock(address), 14)
            addStack(networkChip(network), 12)
            addStack(WalletUi.button(this@ReceiveActivity, "Copy address") { copyAddress() }, 14)
            addStack(
                WalletUi.button(this@ReceiveActivity, "Share address", filled = false) { shareAddress() },
                10,
            )
        }
        root.addStack(addressCard, 18)

        val note = WalletUi.card(this).apply {
            addStack(WalletUi.sectionLabel(this@ReceiveActivity, "Before you share"))
            addStack(
                WalletUi.caption(
                    this@ReceiveActivity,
                    "Receiving is free and needs no passphrase. An address is safe to share — " +
                        "your seed words and passphrase are not, with anyone, ever.",
                ),
                0,
            )
            addStack(
                WalletUi.caption(
                    this@ReceiveActivity,
                    "The same address receives native KUNA and any KVP-102 token someone sends it.",
                ),
                10,
            )
        }
        root.addStack(note, 18)

        setContentView(ScrollView(this).apply {
            isFillViewport = true
            setBackgroundColor(WalletUi.INK)
            addView(root)
        })
    }

    // --- actions -------------------------------------------------------------------------

    private fun copyAddress() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        if (clipboard == null) {
            setStatus("Couldn't reach the clipboard on this device.", Tone.WARN)
            return
        }
        clipboard.setPrimaryClip(ClipData.newPlainText("Kovanica address", address))
        setStatus("Address copied. Share it to receive KUNA or tokens.", Tone.OK)
    }

    private fun shareAddress() {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, address)
            putExtra(Intent.EXTRA_SUBJECT, "Kovanica address")
        }
        startActivity(Intent.createChooser(send, "Share address"))
    }

    // --- rendering -----------------------------------------------------------------------

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

    private fun networkChip(network: String): TextView = TextView(this).apply {
        text = "Receives on $network"
        setTextColor(WalletUi.ACCENT)
        typeface = Typeface.DEFAULT_BOLD
        textSize = 12f
        val pad = dp(10)
        setPadding(pad, dp(5), pad, dp(5))
        background = WalletUi.rounded(this@ReceiveActivity, WalletUi.ACCENT_BG, 10)
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        )
    }

    /**
     * The address as a scannable QR code, centred in the card. A code is only as
     * good as its contrast, so the modules are the plain black-on-white a camera
     * expects rather than the app's ink palette.
     */
    private fun qrBlock(contents: String): View {
        val size = dp(240)
        val bitmap = try {
            qrBitmap(contents, size)
        } catch (error: Exception) {
            return WalletUi.caption(this, "Couldn't draw a QR code on this device — use Copy or Share above.")
        }
        val image = ImageView(this).apply {
            setImageBitmap(bitmap)
            scaleType = ImageView.ScaleType.FIT_CENTER
            contentDescription = "QR code for your address"
        }
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addStack(
                LinearLayout(this@ReceiveActivity).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER
                    addView(image, LinearLayout.LayoutParams(size, size))
                },
                0,
            )
            addStack(
                WalletUi.caption(
                    this@ReceiveActivity,
                    "Point a camera at this code to read your address — for example with Scan a " +
                        "code on the send screen.",
                ),
                10,
            )
        }
    }

    /** Encode [contents] as a square QR bitmap, black modules on white. */
    private fun qrBitmap(contents: String, sizePx: Int): Bitmap {
        val hints = mapOf(
            EncodeHintType.CHARACTER_SET to "UTF-8",
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
            EncodeHintType.MARGIN to 4,
        )
        val matrix = QRCodeWriter().encode(contents, BarcodeFormat.QR_CODE, sizePx, sizePx, hints)
        val pixels = IntArray(sizePx * sizePx)
        for (y in 0 until sizePx) {
            val offset = y * sizePx
            for (x in 0 until sizePx) {
                pixels[offset + x] = if (matrix.get(x, y)) QR_DARK else QR_LIGHT
            }
        }
        return Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888).apply {
            setPixels(pixels, 0, sizePx, 0, 0, sizePx, sizePx)
        }
    }

    private fun header(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(TextView(this@ReceiveActivity).apply {
            text = "KVNC · RECEIVE"
            setTextColor(WalletUi.ACCENT)
            textSize = 11f
            letterSpacing = 0.22f
            typeface = Typeface.DEFAULT_BOLD
        })
        addView(TextView(this@ReceiveActivity).apply {
            text = "Receive"
            setTextColor(WalletUi.TEXT)
            textSize = 30f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, dp(6), 0, 0)
        })
        addView(TextView(this@ReceiveActivity).apply {
            text = "Your keys stay on this phone. An address is all anyone needs to pay you."
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
        const val EXTRA_ADDRESS: String = "io.kovanica.wallet.RECEIVE_ADDRESS"
        const val EXTRA_NETWORK: String = "io.kovanica.wallet.RECEIVE_NETWORK"

        /** Plain black-on-white module colours, for the best chance any camera reads the code. */
        private val QR_DARK: Int = 0xFF000000.toInt()
        private val QR_LIGHT: Int = 0xFFFFFFFF.toInt()
    }
}

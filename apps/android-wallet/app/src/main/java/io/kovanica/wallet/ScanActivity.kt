package io.kovanica.wallet

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.graphics.Matrix
import android.graphics.RectF
import android.graphics.SurfaceTexture
import android.graphics.Typeface
import android.graphics.drawable.ColorDrawable
import android.hardware.camera2.CameraAccessException
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.media.Image
import android.media.ImageReader
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.util.Size
import android.view.Surface
import android.view.TextureView
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import kotlin.math.max
import kotlin.math.roundToInt

/**
 * In-app QR scanner for the send flow. It opens the back camera, previews it
 * with `TextureView`, and decodes each frame with the vendored zxing core
 * reader. Nothing leaves the phone: the frames are read straight out of the
 * camera's YUV buffer and thrown away, and only a decoded address is handed
 * back to [MainActivity] through the classic `setResult` contract.
 *
 * The framework camera2 APIs are used directly — this app carries no androidx,
 * so there is no ActivityCompat or CameraX to lean on, and the permission is
 * requested with [checkSelfPermission] / [requestPermissions].
 *
 * Laid out programmatically — this app has no `res/` and no Compose.
 */
class ScanActivity : Activity(), TextureView.SurfaceTextureListener {
    private lateinit var preview: TextureView
    private lateinit var status: TextView

    @Volatile
    private var camera: CameraDevice? = null

    @Volatile
    private var session: CameraCaptureSession? = null

    private var reader: ImageReader? = null
    private var previewSurface: Surface? = null
    private var previewSize: Size? = null

    private var thread: HandlerThread? = null
    private var handler: Handler? = null

    @Volatile
    private var done = false

    @Volatile
    private var ignoreUntil = 0L

    private var askedPermission = false

    private val decoder = MultiFormatReader().apply {
        setHints(
            mapOf(
                DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
                DecodeHintType.TRY_HARDER to true,
            ),
        )
    }

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
        setStatus("Point the camera at an address QR code.", Tone.NEUTRAL)

        preview = TextureView(this).apply {
            surfaceTextureListener = this@ScanActivity
            background = WalletUi.rounded(this@ScanActivity, WalletUi.SURFACE_2, 14)
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(24), dp(20), dp(36))
            setBackgroundColor(WalletUi.INK)
        }
        root.addView(header())
        root.addView(
            View(this).apply { background = WalletUi.rounded(this@ScanActivity, WalletUi.ACCENT, 2) },
            LinearLayout.LayoutParams(dp(40), dp(3)).apply { topMargin = dp(14) },
        )
        root.addStack(status, 18)
        root.addStack(viewfinder(), 18)
        root.addStack(
            WalletUi.caption(
                this,
                "Hold the phone steady and fill the frame with the code. It reads the address " +
                    "and hands it back to the send field — no picture is saved or uploaded.",
            ),
            14,
        )
        root.addStack(WalletUi.button(this, "Cancel", filled = false) { finish() }, 18)

        setContentView(ScrollView(this).apply {
            isFillViewport = true
            setBackgroundColor(WalletUi.INK)
            addView(root)
        })
    }

    override fun onResume() {
        super.onResume()
        when {
            hasCameraPermission() -> startCameraIfReady()
            !askedPermission -> {
                askedPermission = true
                requestPermissions(arrayOf(Manifest.permission.CAMERA), REQUEST_CAMERA)
            }
            else -> setStatus(cameraOffMessage(), Tone.WARN)
        }
    }

    override fun onPause() {
        super.onPause()
        stopCamera()
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQUEST_CAMERA) return
        if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            setStatus("Point the camera at an address QR code.", Tone.NEUTRAL)
            startCameraIfReady()
        } else {
            setStatus(cameraOffMessage(), Tone.WARN)
        }
    }

    // --- camera lifecycle ----------------------------------------------------------------

    private fun hasCameraPermission(): Boolean =
        checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED

    private fun startCameraIfReady() {
        if (done || camera != null) return
        if (!hasCameraPermission()) return
        if (!preview.isAvailable) return
        startBackgroundThread()
        openCamera()
    }

    /** The camera callbacks and frame decoding run off the UI thread. */
    private fun startBackgroundThread() {
        if (thread != null) return
        val worker = HandlerThread("kvnc-scan")
        worker.start()
        thread = worker
        handler = Handler(worker.looper)
    }

    private fun stopBackgroundThread() {
        handler = null
        thread?.quitSafely()
        thread = null
    }

    private fun openCamera() {
        val manager = getSystemService(Context.CAMERA_SERVICE) as? CameraManager
        if (manager == null) {
            setStatus("This device has no camera the app can use.", Tone.ERROR)
            return
        }
        val texture = preview.surfaceTexture
        if (texture == null) {
            setStatus("The camera view is not ready yet. Try again.", Tone.WARN)
            return
        }
        try {
            val id = pickCameraId(manager)
            if (id == null) {
                setStatus("No camera found on this device.", Tone.ERROR)
                return
            }
            val map = manager.getCameraCharacteristics(id)
                .get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
            if (map == null) {
                setStatus("This camera cannot stream a preview for scanning.", Tone.ERROR)
                return
            }
            val chosenPreview = chooseSize(map.getOutputSizes(SurfaceTexture::class.java), PREFERRED_PREVIEW)
            val chosenAnalysis = chooseSize(map.getOutputSizes(ImageFormat.YUV_420_888), PREFERRED_ANALYSIS)
            if (chosenPreview == null || chosenAnalysis == null) {
                setStatus("This camera does not offer a size the scanner can use.", Tone.ERROR)
                return
            }
            previewSize = chosenPreview

            texture.setDefaultBufferSize(chosenPreview.width, chosenPreview.height)
            val surface = Surface(texture)
            previewSurface = surface

            reader?.close()
            val frameReader = ImageReader.newInstance(
                chosenAnalysis.width,
                chosenAnalysis.height,
                ImageFormat.YUV_420_888,
                MAX_IMAGES,
            )
            frameReader.setOnImageAvailableListener(
                object : ImageReader.OnImageAvailableListener {
                    override fun onImageAvailable(source: ImageReader) = onFrame(source)
                },
                handler,
            )
            reader = frameReader

            manager.openCamera(id, deviceCallback(surface, frameReader), handler)
            configureTransform(preview.width, preview.height)
        } catch (error: SecurityException) {
            setStatus("Camera access was refused. Allow the camera to scan a code.", Tone.ERROR)
        } catch (error: CameraAccessException) {
            setStatus("Couldn't open the camera on this device.", Tone.ERROR)
        } catch (error: IllegalArgumentException) {
            setStatus("This camera rejected the scanner's settings.", Tone.ERROR)
        }
    }

    private fun deviceCallback(previewTarget: Surface, imageReader: ImageReader) =
        object : CameraDevice.StateCallback() {
            override fun onOpened(device: CameraDevice) {
                camera = device
                startPreview(device, previewTarget, imageReader)
            }

            override fun onDisconnected(device: CameraDevice) {
                device.close()
                if (camera === device) camera = null
            }

            override fun onError(device: CameraDevice, error: Int) {
                device.close()
                if (camera === device) camera = null
                runOnUiThread { setStatus("The camera stopped with an error. Try again.", Tone.ERROR) }
            }
        }

    private fun startPreview(device: CameraDevice, previewTarget: Surface, imageReader: ImageReader) {
        try {
            val request = device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
                addTarget(previewTarget)
                addTarget(imageReader.surface)
                set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
                set(CaptureRequest.CONTROL_AE_MODE, CaptureRequest.CONTROL_AE_MODE_ON)
            }
            device.createCaptureSession(
                listOf(previewTarget, imageReader.surface),
                object : CameraCaptureSession.StateCallback() {
                    override fun onConfigured(configured: CameraCaptureSession) {
                        if (camera == null) return
                        session = configured
                        try {
                            configured.setRepeatingRequest(request.build(), null, handler)
                        } catch (error: CameraAccessException) {
                            runOnUiThread { setStatus("The camera preview stopped.", Tone.ERROR) }
                        } catch (error: IllegalStateException) {
                            runOnUiThread { setStatus("The camera preview stopped.", Tone.ERROR) }
                        }
                    }

                    override fun onConfigureFailed(configured: CameraCaptureSession) {
                        runOnUiThread { setStatus("The camera could not start on this device.", Tone.ERROR) }
                    }
                },
                handler,
            )
        } catch (error: CameraAccessException) {
            runOnUiThread { setStatus("Could not start the camera preview.", Tone.ERROR) }
        }
    }

    private fun stopCamera() {
        session?.close()
        session = null
        camera?.close()
        camera = null
        reader?.close()
        reader = null
        previewSurface?.release()
        previewSurface = null
        stopBackgroundThread()
    }

    // --- decoding ------------------------------------------------------------------------

    private fun onFrame(source: ImageReader) {
        val image = try {
            source.acquireLatestImage()
        } catch (_: IllegalStateException) {
            null
        } ?: return
        try {
            if (done) return
            if (System.currentTimeMillis() < ignoreUntil) return
            handleText(decode(image) ?: return)
        } finally {
            image.close()
        }
    }

    /** Decode the luma plane of one YUV frame, or null when no code is present. */
    private fun decode(image: Image): String? {
        val plane = image.planes.firstOrNull() ?: return null
        val width = image.width
        val height = image.height
        val rowStride = plane.rowStride
        val pixelStride = plane.pixelStride
        val buffer = plane.buffer
        buffer.rewind()

        val luma: ByteArray
        val dataWidth: Int
        if (pixelStride == 1) {
            luma = ByteArray(buffer.remaining())
            buffer.get(luma)
            dataWidth = rowStride
        } else {
            // A few sensors pad each luma sample; repack so every row is contiguous.
            val packed = ByteArray(width * height)
            val row = ByteArray(rowStride)
            var written = 0
            for (y in 0 until height) {
                if (written >= packed.size) break
                buffer.position((y * rowStride).coerceAtMost(buffer.limit()))
                val length = minOf(rowStride, buffer.remaining())
                if (length <= 0) break
                buffer.get(row, 0, length)
                var x = 0
                var i = 0
                while (x < width && i < length) {
                    packed[written++] = row[i]
                    i += pixelStride
                    x++
                }
            }
            luma = packed
            dataWidth = width
        }

        val source = PlanarYUVLuminanceSource(luma, dataWidth, height, 0, 0, width, height, false)
        val bitmap = BinaryBitmap(HybridBinarizer(source))
        return try {
            decoder.decodeWithState(bitmap).text
        } catch (_: Exception) {
            null
        } finally {
            decoder.reset()
        }
    }

    private fun handleText(text: String) {
        if (done) return
        val trimmed = text.trim()
        if (KvncAddress.isValid(trimmed, NetworkPrefs.chainId(this))) {
            done = true
            runOnUiThread {
                setResult(RESULT_OK, Intent().putExtra(EXTRA_RESULT_ADDRESS, trimmed))
                finish()
            }
            return
        }
        // Not an address: say so once, then hold off re-reading the same code for a moment.
        ignoreUntil = System.currentTimeMillis() + REJECT_HOLD_MS
        runOnUiThread {
            setStatus("That code is not a Kovanica address. Point the camera at an address code.", Tone.ERROR)
        }
    }

    // --- texture callbacks ---------------------------------------------------------------

    override fun onSurfaceTextureAvailable(surface: SurfaceTexture, width: Int, height: Int) {
        configureTransform(width, height)
        startCameraIfReady()
    }

    override fun onSurfaceTextureSizeChanged(surface: SurfaceTexture, width: Int, height: Int) {
        configureTransform(width, height)
    }

    override fun onSurfaceTextureDestroyed(surface: SurfaceTexture): Boolean {
        stopCamera()
        return true
    }

    override fun onSurfaceTextureUpdated(surface: SurfaceTexture) {}

    /** Centre-crop the preview so the frame fills the box without stretching. */
    private fun configureTransform(viewWidth: Int, viewHeight: Int) {
        val size = previewSize ?: return
        if (viewWidth == 0 || viewHeight == 0) return
        val rotation = windowManager.defaultDisplay.rotation
        val matrix = Matrix()
        val viewRect = RectF(0f, 0f, viewWidth.toFloat(), viewHeight.toFloat())
        val bufferRect = RectF(0f, 0f, size.height.toFloat(), size.width.toFloat())
        val centerX = viewRect.centerX()
        val centerY = viewRect.centerY()
        if (rotation == Surface.ROTATION_90 || rotation == Surface.ROTATION_270) {
            bufferRect.offset(centerX - bufferRect.centerX(), centerY - bufferRect.centerY())
            matrix.setRectToRect(viewRect, bufferRect, Matrix.ScaleToFit.FILL)
            val scale = max(viewHeight.toFloat() / size.height, viewWidth.toFloat() / size.width)
            matrix.postScale(scale, scale, centerX, centerY)
            matrix.postRotate((90 * (rotation - 2)).toFloat(), centerX, centerY)
        } else if (rotation == Surface.ROTATION_180) {
            matrix.postRotate(180f, centerX, centerY)
        }
        preview.setTransform(matrix)
    }

    // --- helpers -------------------------------------------------------------------------

    private fun pickCameraId(manager: CameraManager): String? = try {
        manager.cameraIdList.firstOrNull { id ->
            manager.getCameraCharacteristics(id).get(CameraCharacteristics.LENS_FACING) ==
                CameraCharacteristics.LENS_FACING_BACK
        } ?: manager.cameraIdList.firstOrNull()
    } catch (_: CameraAccessException) {
        null
    }

    private fun chooseSize(sizes: Array<Size>?, preferred: Size): Size? {
        if (sizes == null || sizes.isEmpty()) return null
        return sizes
            .filter { it.width <= preferred.width && it.height <= preferred.height }
            .maxByOrNull { it.width * it.height }
            ?: sizes.minByOrNull { it.width * it.height }
    }

    private fun cameraOffMessage(): String =
        "Camera access is off, so no code can be read. Turn it on for Kovanica in Android " +
            "settings, or type the address instead."

    // --- chrome --------------------------------------------------------------------------

    private fun viewfinder(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = WalletUi.rounded(this@ScanActivity, WalletUi.INK, 18, WalletUi.LINE, 1)
        setPadding(dp(8), dp(8), dp(8), dp(8))
        addView(
            preview,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(320),
            ),
        )
    }

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
        addView(TextView(this@ScanActivity).apply {
            text = "KVNC · SCAN"
            setTextColor(WalletUi.ACCENT)
            textSize = 11f
            letterSpacing = 0.22f
            typeface = Typeface.DEFAULT_BOLD
        })
        addView(TextView(this@ScanActivity).apply {
            text = "Scan a code"
            setTextColor(WalletUi.TEXT)
            textSize = 30f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, dp(6), 0, 0)
        })
        addView(TextView(this@ScanActivity).apply {
            text = "Read a Kovanica address from a QR code and drop it into the send field."
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
        /** The decoded address, in whatever form the code carried, when [RESULT_OK]. */
        const val EXTRA_RESULT_ADDRESS: String = "io.kovanica.wallet.SCAN_RESULT"

        private const val REQUEST_CAMERA: Int = 41

        /** Two buffers is enough for `acquireLatestImage`; more only wastes memory. */
        private const val MAX_IMAGES: Int = 2

        /** After a code that is not an address, wait this long before reading again. */
        private const val REJECT_HOLD_MS: Long = 2000L

        private val PREFERRED_PREVIEW: Size = Size(1920, 1080)
        private val PREFERRED_ANALYSIS: Size = Size(1280, 720)
    }
}

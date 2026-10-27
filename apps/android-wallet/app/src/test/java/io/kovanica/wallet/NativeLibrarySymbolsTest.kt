package io.kovanica.wallet

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * The home screen loads `libkovanica_light_ffi.so` from `refreshFaucet()`.
 * JNA looks up every UniFFI symbol while doing that. A library built before
 * `change_passphrase_raw`, `reveal_mnemonic_raw`, and `contract_address_for_raw`
 * were exported is missing those symbols, and the process dies with
 * `UnsatisfiedLinkError` before the first frame.
 */
class NativeLibrarySymbolsTest {
    @Test
    fun bundledLibraryExportsEveryBindingSymbol() {
        val module = moduleDir()
        val so = File(module, "src/main/jniLibs/arm64-v8a/libkovanica_light_ffi.so")
        val bindings = File(module, "src/main/java/uniffi/kovanica_light/kovanica_light.kt")
        assertTrue(
            "missing ${so.path}. Rebuild with: cargo ndk -t arm64-v8a " +
                "-o app/src/main/jniLibs build -p kovanica-light-ffi --release",
            so.isFile,
        )
        assertTrue(bindings.isFile)
        val exported = ElfSymbols.dynamic(so.readBytes())
        val needed = SYMBOL.findAll(bindings.readText()).map { it.value }.toSet()
        val missing = (needed - exported).sorted()
        assertTrue(
            "stale libkovanica_light_ffi.so is missing symbols JNA registers at launch:\n" +
                missing.joinToString("\n"),
            missing.isEmpty(),
        )
        assertTrue(
            "arm64 library is not 16 KB aligned (Android 15 refuses to load it)",
            ElfSymbols.minLoadAlign(so.readBytes()) >= 0x4000,
        )
    }

    private fun moduleDir(): File {
        val candidates = listOf(File("."), File("app"), File("apps/android-wallet/app"))
        return candidates.firstOrNull {
            File(it, "src/main/jniLibs/arm64-v8a/libkovanica_light_ffi.so").isFile
        } ?: File(".")
    }

    companion object {
        private val SYMBOL = Regex("uniffi_kovanica_light_ffi_[A-Za-z0-9_]+")
    }
}

/** Just enough of ELF64 to read `.dynsym` and `PT_LOAD` alignment. */
internal object ElfSymbols {
    fun dynamic(bytes: ByteArray): Set<String> {
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        require(bytes.size > 64 && bytes[0] == 0x7f.toByte() && bytes[1] == 'E'.code.toByte()) {
            "not an ELF file"
        }
        val shOff = buf.getLong(40)
        val shEnt = buf.getShort(58).toInt() and 0xffff
        val shNum = buf.getShort(60).toInt() and 0xffff
        val shStrNdx = buf.getShort(62).toInt() and 0xffff
        var dynsym = -1
        var dynstr = -1
        for (i in 0 until shNum) {
            val off = shOff + i.toLong() * shEnt
            val type = buf.getInt(off.toInt() + 4)
            if (type == 11) { // SHT_DYNSYM
                dynsym = i
                dynstr = buf.getInt(off.toInt() + 40)
            }
        }
        require(dynsym >= 0 && dynstr >= 0) { "no dynamic symbol table" }
        val symOff = sectionOffset(buf, shOff, shEnt, dynsym)
        val symSize = sectionSize(buf, shOff, shEnt, dynsym)
        val ent = sectionEntSize(buf, shOff, shEnt, dynsym).toInt()
        val strOff = sectionOffset(buf, shOff, shEnt, dynstr)
        val names = HashSet<String>()
        var cursor = symOff
        val end = symOff + symSize
        while (cursor + ent <= end) {
            val nameOff = buf.getInt(cursor.toInt())
            if (nameOff != 0) {
                names.add(cstring(bytes, (strOff + nameOff).toInt()))
            }
            cursor += ent
        }
        require(shStrNdx >= 0)
        return names
    }

    fun minLoadAlign(bytes: ByteArray): Long {
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val phOff = buf.getLong(32)
        val phEnt = buf.getShort(54).toInt() and 0xffff
        val phNum = buf.getShort(56).toInt() and 0xffff
        var min = Long.MAX_VALUE
        for (i in 0 until phNum) {
            val off = (phOff + i.toLong() * phEnt).toInt()
            val type = buf.getInt(off)
            if (type == 1) { // PT_LOAD
                val align = buf.getLong(off + 48)
                if (align < min) min = align
            }
        }
        return min
    }

    private fun sectionOffset(buf: ByteBuffer, shOff: Long, shEnt: Int, index: Int): Long =
        buf.getLong((shOff + index.toLong() * shEnt + 24).toInt())

    private fun sectionSize(buf: ByteBuffer, shOff: Long, shEnt: Int, index: Int): Long =
        buf.getLong((shOff + index.toLong() * shEnt + 32).toInt())

    private fun sectionEntSize(buf: ByteBuffer, shOff: Long, shEnt: Int, index: Int): Long =
        buf.getLong((shOff + index.toLong() * shEnt + 56).toInt())

    private fun cstring(bytes: ByteArray, start: Int): String {
        var end = start
        while (end < bytes.size && bytes[end] != 0.toByte()) end++
        return String(bytes, start, end - start, Charsets.UTF_8)
    }
}

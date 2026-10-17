package id.fatarc.trustgate.testing

import java.io.ByteArrayOutputStream

/** A minimal DER writer, enough to build attestation records and certificates by hand. */
object DerWriter {
    fun sequence(vararg children: ByteArray): ByteArray = tlv(0x30, children.fold(ByteArray(0)) { acc, child -> acc + child })

    fun set(vararg children: ByteArray): ByteArray = tlv(0x31, children.fold(ByteArray(0)) { acc, child -> acc + child })

    fun integer(value: Int): ByteArray = tlv(0x02, minimalBytes(value))

    fun enumerated(value: Int): ByteArray = tlv(0x0A, minimalBytes(value))

    fun boolean(value: Boolean): ByteArray = tlv(0x01, byteArrayOf(if (value) 0xFF.toByte() else 0))

    fun octetString(content: ByteArray): ByteArray = tlv(0x04, content)

    fun utf8String(value: String): ByteArray = tlv(0x0C, value.toByteArray())

    fun utcTime(value: String): ByteArray = tlv(0x17, value.toByteArray())

    /** A BIT STRING with no unused bits, as signatures are encoded. */
    fun bitString(content: ByteArray): ByteArray = tlv(0x03, byteArrayOf(0) + content)

    fun oid(vararg arcs: Long): ByteArray {
        val body = ByteArrayOutputStream()
        body.write((arcs[0] * 40 + arcs[1]).toInt())
        arcs.drop(2).forEach { arc ->
            val groups = generateSequence(arc) { it shr 7 }.takeWhile { it > 0 }.map { (it and 0x7F).toInt() }.toList().reversed()
                .ifEmpty { listOf(0) }
            groups.forEachIndexed { index, group -> body.write(if (index < groups.lastIndex) group or 0x80 else group) }
        }
        return tlv(0x06, body.toByteArray())
    }

    /** [tagNumber] EXPLICIT, in the context-specific constructed form, including high tag numbers. */
    fun explicit(tagNumber: Int, inner: ByteArray): ByteArray {
        if (tagNumber < 0x1F) return tlv(0xA0 or tagNumber, inner)
        val tag = ByteArrayOutputStream()
        tag.write(0xBF)
        val groups = generateSequence(tagNumber) { it shr 7 }.takeWhile { it > 0 }.map { it and 0x7F }.toList().reversed()
        groups.forEachIndexed { index, group -> tag.write(if (index < groups.lastIndex) group or 0x80 else group) }
        return tag.toByteArray() + length(inner.size) + inner
    }

    fun tlv(tag: Int, content: ByteArray): ByteArray = byteArrayOf(tag.toByte()) + length(content.size) + content

    private fun length(size: Int): ByteArray = when {
        size < 0x80 -> byteArrayOf(size.toByte())
        size <= 0xFF -> byteArrayOf(0x81.toByte(), size.toByte())
        else -> byteArrayOf(0x82.toByte(), (size shr 8).toByte(), size.toByte())
    }

    private fun minimalBytes(value: Int): ByteArray = when {
        value in 0..0x7F -> byteArrayOf(value.toByte())
        else -> byteArrayOf((value shr 8).toByte(), value.toByte())
    }
}

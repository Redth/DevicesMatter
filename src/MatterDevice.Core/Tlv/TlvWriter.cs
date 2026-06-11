using System.Buffers.Binary;
using System.Text;

namespace MatterDevice.Core.Tlv;

/// <summary>
/// Writes Matter TLV (Matter Core Spec, Appendix A). Little-endian; integers are emitted in the
/// smallest width that holds the value (receivers must accept any width). Covers the element set the
/// commissioning and interaction-model messages need: structures/arrays/lists, context &amp; anonymous
/// tags, (un)signed ints, booleans, UTF-8/byte strings, and null.
/// </summary>
public sealed class TlvWriter
{
    private byte[] _buffer;
    private int _length;
    private int _depth;

    public TlvWriter(int initialCapacity = 64) => _buffer = new byte[Math.Max(16, initialCapacity)];

    /// <summary>The bytes written so far.</summary>
    public ReadOnlySpan<byte> WrittenSpan => _buffer.AsSpan(0, _length);

    public byte[] ToArray() => _buffer.AsSpan(0, _length).ToArray();

    /// <summary>Appends a complete pre-encoded TLV element (control byte ‖ tag ‖ value) verbatim.</summary>
    public TlvWriter WriteRawElement(ReadOnlySpan<byte> preEncoded)
    {
        WriteRaw(preEncoded);
        return this;
    }

    // ---- containers ------------------------------------------------------

    public TlvWriter StartStructure(TlvTag tag) => StartContainer(tag, TlvElementType.Structure);
    public TlvWriter StartArray(TlvTag tag) => StartContainer(tag, TlvElementType.Array);
    public TlvWriter StartList(TlvTag tag) => StartContainer(tag, TlvElementType.List);

    public TlvWriter EndContainer()
    {
        if (_depth == 0)
            throw new InvalidOperationException("EndContainer with no open container.");
        _depth--;
        WriteByte((byte)TlvElementType.EndOfContainer);
        return this;
    }

    private TlvWriter StartContainer(TlvTag tag, TlvElementType type)
    {
        WriteControlAndTag(tag, type);
        _depth++;
        return this;
    }

    // ---- scalars ---------------------------------------------------------

    public TlvWriter WriteBool(TlvTag tag, bool value)
    {
        WriteControlAndTag(tag, value ? TlvElementType.BooleanTrue : TlvElementType.BooleanFalse);
        return this;
    }

    public TlvWriter WriteNull(TlvTag tag)
    {
        WriteControlAndTag(tag, TlvElementType.Null);
        return this;
    }

    public TlvWriter WriteUInt(TlvTag tag, ulong value)
    {
        if (value <= byte.MaxValue)
        {
            WriteControlAndTag(tag, TlvElementType.UnsignedInt1);
            WriteByte((byte)value);
        }
        else if (value <= ushort.MaxValue)
        {
            WriteControlAndTag(tag, TlvElementType.UnsignedInt2);
            WriteUInt16((ushort)value);
        }
        else if (value <= uint.MaxValue)
        {
            WriteControlAndTag(tag, TlvElementType.UnsignedInt4);
            WriteUInt32((uint)value);
        }
        else
        {
            WriteControlAndTag(tag, TlvElementType.UnsignedInt8);
            WriteUInt64(value);
        }
        return this;
    }

    public TlvWriter WriteInt(TlvTag tag, long value)
    {
        if (value is >= sbyte.MinValue and <= sbyte.MaxValue)
        {
            WriteControlAndTag(tag, TlvElementType.SignedInt1);
            WriteByte((byte)(sbyte)value);
        }
        else if (value is >= short.MinValue and <= short.MaxValue)
        {
            WriteControlAndTag(tag, TlvElementType.SignedInt2);
            WriteUInt16((ushort)(short)value);
        }
        else if (value is >= int.MinValue and <= int.MaxValue)
        {
            WriteControlAndTag(tag, TlvElementType.SignedInt4);
            WriteUInt32((uint)(int)value);
        }
        else
        {
            WriteControlAndTag(tag, TlvElementType.SignedInt8);
            WriteUInt64((ulong)value);
        }
        return this;
    }

    public TlvWriter WriteBytes(TlvTag tag, ReadOnlySpan<byte> value)
    {
        WriteLengthPrefixed(tag, value,
            TlvElementType.ByteString1, TlvElementType.ByteString2, TlvElementType.ByteString4);
        return this;
    }

    public TlvWriter WriteString(TlvTag tag, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        WriteLengthPrefixed(tag, bytes,
            TlvElementType.Utf8String1, TlvElementType.Utf8String2, TlvElementType.Utf8String4);
        return this;
    }

    private void WriteLengthPrefixed(TlvTag tag, ReadOnlySpan<byte> value,
        TlvElementType t1, TlvElementType t2, TlvElementType t4)
    {
        if (value.Length <= byte.MaxValue)
        {
            WriteControlAndTag(tag, t1);
            WriteByte((byte)value.Length);
        }
        else if (value.Length <= ushort.MaxValue)
        {
            WriteControlAndTag(tag, t2);
            WriteUInt16((ushort)value.Length);
        }
        else
        {
            WriteControlAndTag(tag, t4);
            WriteUInt32((uint)value.Length);
        }
        WriteRaw(value);
    }

    // ---- control byte + tag ---------------------------------------------

    private void WriteControlAndTag(TlvTag tag, TlvElementType type)
    {
        if (tag.IsAnonymous)
        {
            WriteByte((byte)((byte)TlvTagControl.Anonymous | (byte)type));
        }
        else if (tag.IsContextSpecific)
        {
            WriteByte((byte)((byte)TlvTagControl.ContextSpecific | (byte)type));
            WriteByte((byte)tag.TagNumber);
        }
        else
        {
            // Fully-qualified / profile-specific tags aren't needed by the spike's messages.
            throw new NotSupportedException("Only anonymous and context-specific tags are implemented.");
        }
    }

    // ---- raw buffer ------------------------------------------------------

    private void WriteByte(byte b)
    {
        EnsureCapacity(1);
        _buffer[_length++] = b;
    }

    private void WriteUInt16(ushort v)
    {
        EnsureCapacity(2);
        BinaryPrimitives.WriteUInt16LittleEndian(_buffer.AsSpan(_length), v);
        _length += 2;
    }

    private void WriteUInt32(uint v)
    {
        EnsureCapacity(4);
        BinaryPrimitives.WriteUInt32LittleEndian(_buffer.AsSpan(_length), v);
        _length += 4;
    }

    private void WriteUInt64(ulong v)
    {
        EnsureCapacity(8);
        BinaryPrimitives.WriteUInt64LittleEndian(_buffer.AsSpan(_length), v);
        _length += 8;
    }

    private void WriteRaw(ReadOnlySpan<byte> bytes)
    {
        EnsureCapacity(bytes.Length);
        bytes.CopyTo(_buffer.AsSpan(_length));
        _length += bytes.Length;
    }

    private void EnsureCapacity(int extra)
    {
        if (_length + extra <= _buffer.Length)
            return;
        var newSize = Math.Max(_buffer.Length * 2, _length + extra);
        Array.Resize(ref _buffer, newSize);
    }
}

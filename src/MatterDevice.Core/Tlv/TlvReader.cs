using System.Buffers.Binary;
using System.Text;

namespace MatterDevice.Core.Tlv;

/// <summary>
/// A forward-only pull reader for Matter TLV (Matter Core Spec, Appendix A) — the decode counterpart to
/// <see cref="TlvWriter"/>. Each <see cref="Read"/> advances to the next element and exposes its tag,
/// type, and value. Only the element/tag set the commissioning + interaction-model messages use is
/// handled (anonymous &amp; context-specific tags; ints, bools, strings, byte strings, null, containers).
/// </summary>
public ref struct TlvReader
{
    private readonly ReadOnlySpan<byte> _data;
    private int _pos;

    public TlvReader(ReadOnlySpan<byte> data)
    {
        _data = data;
        _pos = 0;
        ElementType = default;
        TagNumber = null;
        _valueStart = 0;
        _valueLength = 0;
        _inlineUnsigned = 0;
        _inlineSigned = 0;
    }

    /// <summary>Element type of the current element (valid after a successful <see cref="Read"/>).</summary>
    public TlvElementType ElementType { get; private set; }

    /// <summary>Context-specific tag number of the current element, or null if anonymous.</summary>
    public int? TagNumber { get; private set; }

    private int _valueStart;
    private int _valueLength;
    private ulong _inlineUnsigned;
    private long _inlineSigned;

    public readonly bool IsContainer =>
        ElementType is TlvElementType.Structure or TlvElementType.Array or TlvElementType.List;

    /// <summary>
    /// Advances to the next element at the current level. Returns false at end of data or when an
    /// EndOfContainer marker is reached (which is consumed).
    /// </summary>
    public bool Read()
    {
        if (_pos >= _data.Length)
            return false;

        var control = _data[_pos++];
        var tagControl = (TlvTagControl)(control & 0xE0);
        ElementType = (TlvElementType)(control & 0x1F);

        if (ElementType == TlvElementType.EndOfContainer)
        {
            TagNumber = null;
            return false;
        }

        TagNumber = tagControl switch
        {
            TlvTagControl.Anonymous => (int?)null,
            TlvTagControl.ContextSpecific => ReadTagByte(),
            _ => throw new NotSupportedException($"Tag control {tagControl} is not implemented."),
        };

        DecodeValue();
        return true;
    }

    private int ReadTagByte() => _data[_pos++];

    private void DecodeValue()
    {
        switch (ElementType)
        {
            case TlvElementType.SignedInt1: _inlineSigned = (sbyte)_data[_pos]; _pos += 1; break;
            case TlvElementType.SignedInt2: _inlineSigned = BinaryPrimitives.ReadInt16LittleEndian(_data.Slice(_pos)); _pos += 2; break;
            case TlvElementType.SignedInt4: _inlineSigned = BinaryPrimitives.ReadInt32LittleEndian(_data.Slice(_pos)); _pos += 4; break;
            case TlvElementType.SignedInt8: _inlineSigned = BinaryPrimitives.ReadInt64LittleEndian(_data.Slice(_pos)); _pos += 8; break;

            case TlvElementType.UnsignedInt1: _inlineUnsigned = _data[_pos]; _pos += 1; break;
            case TlvElementType.UnsignedInt2: _inlineUnsigned = BinaryPrimitives.ReadUInt16LittleEndian(_data.Slice(_pos)); _pos += 2; break;
            case TlvElementType.UnsignedInt4: _inlineUnsigned = BinaryPrimitives.ReadUInt32LittleEndian(_data.Slice(_pos)); _pos += 4; break;
            case TlvElementType.UnsignedInt8: _inlineUnsigned = BinaryPrimitives.ReadUInt64LittleEndian(_data.Slice(_pos)); _pos += 8; break;

            case TlvElementType.BooleanFalse: _inlineUnsigned = 0; break;
            case TlvElementType.BooleanTrue: _inlineUnsigned = 1; break;
            case TlvElementType.Null: break;

            case TlvElementType.Float4: _valueStart = _pos; _valueLength = 4; _pos += 4; break;
            case TlvElementType.Float8: _valueStart = _pos; _valueLength = 8; _pos += 8; break;

            case TlvElementType.Utf8String1:
            case TlvElementType.ByteString1: ReadLengthPrefixed(1); break;
            case TlvElementType.Utf8String2:
            case TlvElementType.ByteString2: ReadLengthPrefixed(2); break;
            case TlvElementType.Utf8String4:
            case TlvElementType.ByteString4: ReadLengthPrefixed(4); break;

            case TlvElementType.Structure:
            case TlvElementType.Array:
            case TlvElementType.List:
                // container: value is read by entering it (Read() recurses at the new level)
                break;

            default:
                throw new NotSupportedException($"Element type {ElementType} is not implemented.");
        }
    }

    private void ReadLengthPrefixed(int lenBytes)
    {
        int len = lenBytes switch
        {
            1 => _data[_pos],
            2 => BinaryPrimitives.ReadUInt16LittleEndian(_data.Slice(_pos)),
            4 => checked((int)BinaryPrimitives.ReadUInt32LittleEndian(_data.Slice(_pos))),
            _ => throw new InvalidOperationException(),
        };
        _pos += lenBytes;
        _valueStart = _pos;
        _valueLength = len;
        _pos += len;
    }

    // ---- value accessors -------------------------------------------------

    public readonly ulong GetUInt() => _inlineUnsigned;
    public readonly long GetInt() => _inlineSigned;
    public readonly bool GetBool() => ElementType == TlvElementType.BooleanTrue;
    public readonly ReadOnlySpan<byte> GetBytes() => _data.Slice(_valueStart, _valueLength);
    public readonly string GetString() => Encoding.UTF8.GetString(_data.Slice(_valueStart, _valueLength));

    // ---- container navigation -------------------------------------------

    /// <summary>
    /// Reads the current container's immediate <b>leaf</b> children, invoking <paramref name="onField"/>
    /// for each. Nested containers are skipped whole (the spike's messages never need to descend into an
    /// optional sub-struct such as session parameters). The reader must currently sit on a container
    /// element just returned by <see cref="Read"/>; afterwards it is positioned past the container.
    /// </summary>
    public void EnterContainer(ReadFieldDelegate onField)
    {
        if (!IsContainer)
            throw new InvalidOperationException("Current element is not a container.");

        var child = new TlvReader(_data) { _pos = _pos };
        while (child.Read())
        {
            if (child.IsContainer)
                child.SkipContainerBody();
            else
                onField(ref child);
        }
        _pos = child._pos;
    }

    /// <summary>
    /// Skips the body of the container the reader just entered (its header element was already read),
    /// consuming through the matching EndOfContainer, honoring nesting.
    /// </summary>
    private void SkipContainerBody()
    {
        var depth = 1;
        while (depth > 0)
        {
            if (_pos >= _data.Length)
                throw new InvalidOperationException("Truncated TLV: unterminated container.");
            var control = _data[_pos++];
            var type = (TlvElementType)(control & 0x1F);
            if (type == TlvElementType.EndOfContainer)
            {
                depth--;
                continue;
            }
            _pos += TagLengthBytes((TlvTagControl)(control & 0xE0));
            if (type is TlvElementType.Structure or TlvElementType.Array or TlvElementType.List)
            {
                depth++;
                continue; // its EndOfContainer will decrement depth
            }
            _pos += ValueLengthBytes(type);
        }
    }

    private static int TagLengthBytes(TlvTagControl tagControl) => tagControl switch
    {
        TlvTagControl.Anonymous => 0,
        TlvTagControl.ContextSpecific => 1,
        TlvTagControl.CommonProfile2 or TlvTagControl.ImplicitProfile2 => 2,
        TlvTagControl.CommonProfile4 or TlvTagControl.ImplicitProfile4 => 4,
        TlvTagControl.FullyQualified6 => 6,
        TlvTagControl.FullyQualified8 => 8,
        _ => 0,
    };

    /// <summary>Bytes consumed by a non-container element's value (including any length prefix).</summary>
    private int ValueLengthBytes(TlvElementType type) => type switch
    {
        TlvElementType.SignedInt1 or TlvElementType.UnsignedInt1 => 1,
        TlvElementType.SignedInt2 or TlvElementType.UnsignedInt2 => 2,
        TlvElementType.SignedInt4 or TlvElementType.UnsignedInt4 or TlvElementType.Float4 => 4,
        TlvElementType.SignedInt8 or TlvElementType.UnsignedInt8 or TlvElementType.Float8 => 8,
        TlvElementType.BooleanFalse or TlvElementType.BooleanTrue or TlvElementType.Null => 0,
        TlvElementType.Utf8String1 or TlvElementType.ByteString1 => 1 + _data[_pos],
        TlvElementType.Utf8String2 or TlvElementType.ByteString2 => 2 + BinaryPrimitives.ReadUInt16LittleEndian(_data.Slice(_pos)),
        TlvElementType.Utf8String4 or TlvElementType.ByteString4 => 4 + checked((int)BinaryPrimitives.ReadUInt32LittleEndian(_data.Slice(_pos))),
        _ => throw new NotSupportedException($"Cannot size element type {type}."),
    };

    public delegate void ReadFieldDelegate(ref TlvReader reader);
}

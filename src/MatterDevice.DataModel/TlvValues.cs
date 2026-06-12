using MatterDevice.Core.Tlv;

namespace MatterDevice.DataModel;

/// <summary>
/// An attribute value that knows how to write itself as TLV — used for structured attributes (structs and
/// lists/arrays) that the scalar encoder in <c>InteractionDispatcher.WriteValue</c> can't express.
/// </summary>
public interface IMatterTlvValue
{
    void WriteTlv(TlvWriter writer, TlvTag tag);
}

/// <summary>A TLV structure attribute: an ordered set of context-tagged members.</summary>
public sealed class TlvStruct : IMatterTlvValue
{
    private readonly List<(int Tag, object? Value)> _members = [];

    public TlvStruct Add(int tag, object? value)
    {
        _members.Add((tag, value));
        return this;
    }

    public void WriteTlv(TlvWriter writer, TlvTag tag)
    {
        writer.StartStructure(tag);
        foreach (var (memberTag, value) in _members)
            InteractionModel.InteractionDispatcher.WriteValue(writer, TlvTag.ContextSpecific(memberTag), value);
        writer.EndContainer();
    }
}

/// <summary>
/// An attribute value captured as a raw TLV element (control ‖ tag ‖ value), used to round-trip structured
/// values — like the Access Control list — that a controller writes and reads back without the device
/// having to model their full shape. Re-tags itself to the requested tag on write.
/// </summary>
public sealed class TlvRawValue(byte[] capturedElement) : IMatterTlvValue
{
    private readonly byte[] _element = capturedElement;

    public void WriteTlv(TlvWriter writer, TlvTag tag)
    {
        var control = _element[0];
        var elementType = (byte)(control & 0x1F);
        var tagControl = control & 0xE0;
        var tagLen = tagControl switch { 0x00 => 0, 0x20 => 1, 0x40 or 0x80 => 2, 0x60 or 0xA0 => 4, 0xC0 => 6, 0xE0 => 8, _ => 0 };
        var value = _element.AsSpan(1 + tagLen);

        var reTagged = new byte[1 + (tag.IsAnonymous ? 0 : 1) + value.Length];
        if (tag.IsAnonymous)
        {
            reTagged[0] = elementType; // anonymous tag control = 0x00
            value.CopyTo(reTagged.AsSpan(1));
        }
        else
        {
            reTagged[0] = (byte)(0x20 | elementType); // context-specific tag control
            reTagged[1] = (byte)tag.TagNumber;
            value.CopyTo(reTagged.AsSpan(2));
        }
        writer.WriteRawElement(reTagged);
    }
}

/// <summary>A TLV array/list attribute: a sequence of anonymous-tagged elements.</summary>
public sealed class TlvArray : IMatterTlvValue
{
    private readonly List<object?> _items;

    public TlvArray(IEnumerable<object?>? items = null) => _items = items?.ToList() ?? [];

    public TlvArray Add(object? value)
    {
        _items.Add(value);
        return this;
    }

    public void WriteTlv(TlvWriter writer, TlvTag tag)
    {
        writer.StartArray(tag);
        foreach (var item in _items)
            InteractionModel.InteractionDispatcher.WriteValue(writer, TlvTag.Anonymous, item);
        writer.EndContainer();
    }
}

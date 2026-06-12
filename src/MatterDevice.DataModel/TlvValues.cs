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

using MatterDevice.Core.Tlv;

namespace MatterDevice.Core.Credentials;

/// <summary>
/// Matter Distinguished Name TLV attribute tags (Matter Core Spec §6.5.6, verified against the CHIP OID
/// generator). String-valued attributes (1–16) OR 0x80 into the tag when PrintableString; the 64-/32-bit
/// Matter id attributes (17–23) are unsigned ints.
/// </summary>
public enum DnAttributeType : byte
{
    CommonName = 1,
    MatterNodeId = 17,
    MatterFirmwareSigningId = 18,
    MatterIcacId = 19,
    MatterRcacId = 20,
    MatterFabricId = 21,
    MatterCaseAuthTag = 22,
}

/// <summary>
/// A Matter Distinguished Name — the ordered list of attributes in a certificate's issuer/subject
/// (Matter Core Spec §6.5.6). Encoded as a TLV <b>List</b>; each attribute's context tag is its
/// <see cref="DnAttributeType"/>.
/// </summary>
public sealed class MatterDistinguishedName
{
    private readonly List<(DnAttributeType Type, ulong IntValue, string? StringValue)> _attributes = [];

    /// <summary>The DN attributes in order (type, integer value for Matter ids, or string value).</summary>
    public IReadOnlyList<(DnAttributeType Type, ulong IntValue, string? StringValue)> Attributes => _attributes;

    public MatterDistinguishedName AddMatterId(DnAttributeType type, ulong value)
    {
        _attributes.Add((type, value, null));
        return this;
    }

    public MatterDistinguishedName AddCommonName(string name)
    {
        _attributes.Add((DnAttributeType.CommonName, 0, name));
        return this;
    }

    public ulong? GetMatterId(DnAttributeType type)
    {
        foreach (var a in _attributes)
            if (a.Type == type && a.StringValue is null)
                return a.IntValue;
        return null;
    }

    public ulong? NodeId => GetMatterId(DnAttributeType.MatterNodeId);
    public ulong? FabricId => GetMatterId(DnAttributeType.MatterFabricId);
    public ulong? RcacId => GetMatterId(DnAttributeType.MatterRcacId);

    public void Write(TlvWriter w, TlvTag tag)
    {
        w.StartList(tag);
        foreach (var (type, intValue, stringValue) in _attributes)
        {
            if (stringValue is not null)
                w.WriteString(TlvTag.ContextSpecific((byte)type), stringValue);
            else
                w.WriteUInt(TlvTag.ContextSpecific((byte)type), intValue);
        }
        w.EndContainer();
    }

    public static MatterDistinguishedName Read(ref TlvReader list)
    {
        var dn = new MatterDistinguishedName();
        list.EnterContainer((ref TlvReader f) =>
        {
            var rawTag = (byte)(f.TagNumber ?? 0);
            var type = (DnAttributeType)(rawTag & 0x7F); // strip the PrintableString flag
            if (rawTag is >= 1 and <= (16 | 0x80) && (rawTag & 0x7F) <= 16)
                dn._attributes.Add((type, 0, f.GetString()));
            else
                dn._attributes.Add((type, f.GetUInt(), null));
        });
        return dn;
    }
}

using MatterDevice.Core.Tlv;

namespace MatterDevice.Commissioning.OperationalCredentials;

/// <summary>
/// Parses an Interaction-Model command's captured CommandFields struct (the bytes captured verbatim by the
/// invoke decoder) into its context-tagged members, so an Operational-Credentials command handler can pull
/// out its arguments (nonces, certificates, the IPK, …) by tag.
/// </summary>
public sealed class OpCredsCommandFields
{
    private readonly Dictionary<int, byte[]> _byteValues = [];
    private readonly Dictionary<int, ulong> _uintValues = [];

    public static OpCredsCommandFields Parse(byte[]? fieldsTlv)
    {
        var fields = new OpCredsCommandFields();
        if (fieldsTlv is null || fieldsTlv.Length == 0)
            return fields;

        var r = new TlvReader(fieldsTlv);
        if (!r.Read() || !r.IsContainer)
            return fields;
        r.EnterContainer((ref TlvReader f) =>
        {
            if (f.TagNumber is not { } tag)
                return;
            switch (f.ElementType)
            {
                case TlvElementType.ByteString1 or TlvElementType.ByteString2 or TlvElementType.ByteString4:
                    fields._byteValues[tag] = f.GetBytes().ToArray();
                    break;
                case TlvElementType.UnsignedInt1 or TlvElementType.UnsignedInt2
                    or TlvElementType.UnsignedInt4 or TlvElementType.UnsignedInt8:
                    fields._uintValues[tag] = f.GetUInt();
                    break;
                case TlvElementType.BooleanTrue: fields._uintValues[tag] = 1; break;
                case TlvElementType.BooleanFalse: fields._uintValues[tag] = 0; break;
            }
        });
        return fields;
    }

    public byte[] Bytes(int tag) => _byteValues.TryGetValue(tag, out var v) ? v : [];
    public ulong UInt(int tag) => _uintValues.GetValueOrDefault(tag);
    public bool Has(int tag) => _byteValues.ContainsKey(tag) || _uintValues.ContainsKey(tag);
}

using MatterDevice.Core.Tlv;

namespace MatterDevice.DataModel.InteractionModel;

/// <summary>Handles an invoked command, returning its status. Wire device behaviour here.</summary>
public delegate ImStatus CommandHandler(Endpoint endpoint, Cluster cluster, InvokedCommand command);

/// <summary>
/// Routes Interaction Model requests against a <see cref="Node"/>: resolves Read attribute paths to values
/// and dispatches Invoke commands. This is the bridge between the IM wire codecs and the device's data
/// model. Subscriptions, writes, wildcard event paths and chunking are follow-on work.
/// </summary>
public sealed class InteractionDispatcher(Node node)
{
    private readonly Node _node = node;

    /// <summary>Resolves a ReadRequest's paths to attribute reports (concrete paths and simple wildcards).</summary>
    public IReadOnlyList<AttributeReport> Read(IReadOnlyList<AttributePath> paths)
    {
        var reports = new List<AttributeReport>();
        foreach (var path in paths)
        {
            foreach (var ep in _node.Endpoints)
            {
                if (path.Endpoint is { } e && e != ep.Id) continue;
                foreach (var cluster in ep.Clusters)
                {
                    if (path.Cluster is { } c && c != cluster.Id) continue;
                    foreach (var (attrId, value) in cluster.Attributes)
                    {
                        if (path.Attribute is { } a && a != attrId) continue;
                        var concretePath = new AttributePath(ep.Id, cluster.Id, attrId);
                        var captured = value;
                        reports.Add(new AttributeReport(concretePath, (w, tag) => WriteValue(w, tag, captured)));
                    }
                }
            }
        }
        return reports;
    }

    /// <summary>Dispatches InvokeRequest commands to <paramref name="handler"/>, mapping unknown paths to status errors.</summary>
    public IReadOnlyList<CommandResult> Invoke(IReadOnlyList<InvokedCommand> commands, CommandHandler handler)
    {
        var results = new List<CommandResult>();
        foreach (var cmd in commands)
        {
            var ep = _node.Endpoints.FirstOrDefault(x => x.Id == cmd.Path.Endpoint);
            if (ep is null) { results.Add(new CommandResult(cmd.Path, ImStatus.UnsupportedEndpoint)); continue; }
            var cluster = ep.Clusters.FirstOrDefault(x => x.Id == cmd.Path.Cluster);
            if (cluster is null) { results.Add(new CommandResult(cmd.Path, ImStatus.UnsupportedCluster)); continue; }
            results.Add(new CommandResult(cmd.Path, handler(ep, cluster, cmd)));
        }
        return results;
    }

    /// <summary>Encodes a stored attribute value as a TLV data element by its runtime type.</summary>
    public static void WriteValue(TlvWriter w, TlvTag tag, object? value)
    {
        switch (value)
        {
            case null: w.WriteNull(tag); break;
            case bool b: w.WriteBool(tag, b); break;
            case sbyte sb: w.WriteInt(tag, sb); break;
            case short s: w.WriteInt(tag, s); break;
            case int i: w.WriteInt(tag, i); break;
            case long l: w.WriteInt(tag, l); break;
            case byte by: w.WriteUInt(tag, by); break;
            case ushort us: w.WriteUInt(tag, us); break;
            case uint ui: w.WriteUInt(tag, ui); break;
            case ulong ul: w.WriteUInt(tag, ul); break;
            case string str: w.WriteString(tag, str); break;
            case byte[] bytes: w.WriteBytes(tag, bytes); break;
            case Enum e: w.WriteUInt(tag, Convert.ToUInt64(e)); break;
            default: throw new NotSupportedException($"No TLV encoding for attribute type {value.GetType()}.");
        }
    }

    /// <summary>Decodes a TLV data element to a CLR value (inverse of <see cref="WriteValue"/>).</summary>
    public static object? ReadValue(ref TlvReader r) => r.ElementType switch
    {
        TlvElementType.Null => null,
        TlvElementType.BooleanTrue or TlvElementType.BooleanFalse => r.GetBool(),
        TlvElementType.UnsignedInt1 or TlvElementType.UnsignedInt2
            or TlvElementType.UnsignedInt4 or TlvElementType.UnsignedInt8 => r.GetUInt(),
        TlvElementType.SignedInt1 or TlvElementType.SignedInt2
            or TlvElementType.SignedInt4 or TlvElementType.SignedInt8 => r.GetInt(),
        TlvElementType.Utf8String1 or TlvElementType.Utf8String2
            or TlvElementType.Utf8String4 => r.GetString(),
        TlvElementType.ByteString1 or TlvElementType.ByteString2
            or TlvElementType.ByteString4 => r.GetBytes().ToArray(),
        _ => throw new NotSupportedException($"No CLR decoding for TLV element {r.ElementType}."),
    };
}

using MatterDevice.Core.Tlv;

namespace MatterDevice.DataModel.InteractionModel;

/// <summary>One invoked command: its path and the raw TLV bytes of its command fields (if any).</summary>
public sealed record InvokedCommand(CommandPath Path, byte[]? FieldsTlv);

/// <summary>
/// The result of executing a command. Either a plain status, or a response command (a command back to the
/// initiator carrying response fields, e.g. AttestationResponse) identified by <see cref="ResponseCommandId"/>
/// with <see cref="WriteResponseFields"/> emitting its TLV members.
/// </summary>
public sealed record CommandResult(CommandPath Path, ImStatus Status)
{
    public uint? ResponseCommandId { get; init; }
    public Action<MatterDevice.Core.Tlv.TlvWriter>? WriteResponseFields { get; init; }

    public bool HasResponseData => ResponseCommandId is not null && WriteResponseFields is not null;
}

/// <summary>
/// InvokeRequest / InvokeResponse codecs (Matter Core Spec §10.7, §8.8–8.9). For the skeleton, a response
/// carries a CommandStatusIB per command; response <i>command data</i> (for commands that return values)
/// is a later addition.
/// </summary>
public static class InvokeInteraction
{
    // InvokeRequestMessage tags
    private const int TagSuppressResponse = 0;
    private const int TagInvokeRequests = 2;

    // CommandDataIB tags
    private const int TagCommandPath = 0;
    private const int TagCommandFields = 1;

    // InvokeResponseMessage tags
    private const int TagInvokeResponses = 1;

    // InvokeResponseIB / CommandStatusIB / StatusIB tags (Matter Core Spec §10.6.12: command[0], status[1])
    private const int TagCommandData = 0;     // InvokeResponseIB → CommandDataIB (response with fields)
    private const int TagStatus = 1;          // InvokeResponseIB → CommandStatusIB
    private const int TagCsCommandPath = 0;   // CommandStatusIB → CommandPathIB
    private const int TagCsStatus = 1;        // CommandStatusIB → StatusIB
    private const int TagStatusCode = 0;      // StatusIB → Status

    /// <summary>
    /// Builds a CommandFields element (a structure under context tag 1) from a member writer — the
    /// pre-encoded value to put in <see cref="InvokedCommand.FieldsTlv"/>.
    /// </summary>
    public static byte[] EncodeCommandFields(Action<TlvWriter> writeMembers)
    {
        var w = new TlvWriter();
        w.StartStructure(TlvTag.ContextSpecific(TagCommandFields));
        writeMembers(w);
        w.EndContainer();
        return w.ToArray();
    }

    /// <summary>Builds an InvokeRequest for the given commands (controller/test side).</summary>
    public static byte[] EncodeRequest(IReadOnlyList<InvokedCommand> commands, bool suppressResponse = false, bool timed = false)
    {
        var w = new TlvWriter();
        w.StartStructure(TlvTag.Anonymous);
        w.WriteBool(TlvTag.ContextSpecific(TagSuppressResponse), suppressResponse);
        w.WriteBool(TlvTag.ContextSpecific(1), timed); // TimedRequest
        w.StartArray(TlvTag.ContextSpecific(TagInvokeRequests));
        foreach (var c in commands)
        {
            w.StartStructure(TlvTag.Anonymous);                         // CommandDataIB
            c.Path.Write(w, TlvTag.ContextSpecific(TagCommandPath));
            if (c.FieldsTlv is { } fields)
                w.WriteRawElement(fields);                              // pre-encoded CommandFields (context tag 1)
            w.EndContainer();                                           // CommandDataIB
        }
        w.EndContainer();
        w.WriteUInt(TlvTag.ContextSpecific(ImConstants.InteractionModelRevisionTag), ImConstants.InteractionModelRevision);
        w.EndContainer();
        return w.ToArray();
    }

    /// <summary>Parses an InvokeRequest, returning the commands to execute.</summary>
    public static IReadOnlyList<InvokedCommand> DecodeRequest(ReadOnlySpan<byte> tlv)
    {
        var commands = new List<InvokedCommand>();
        var r = new TlvReader(tlv);
        if (!r.Read() || !r.IsContainer) throw new FormatException("InvokeRequest: expected a struct.");
        r.EnterContainer((ref TlvReader f) =>
        {
            if (f.TagNumber == TagInvokeRequests && f.IsContainer)
            {
                f.EnterContainer((ref TlvReader cmd) =>
                {
                    if (!cmd.IsContainer) return;
                    CommandPath? path = null;
                    byte[]? fields = null;
                    cmd.EnterContainer((ref TlvReader g) =>
                    {
                        if (g.TagNumber == TagCommandPath && g.IsContainer)
                            path = CommandPath.Read(ref g);
                        else if (g.TagNumber == TagCommandFields)
                            fields = g.CurrentElementSpan.ToArray(); // capture the fields struct verbatim
                    });
                    if (path is { } p)
                        commands.Add(new InvokedCommand(p, fields));
                });
            }
        });
        return commands;
    }

    /// <summary>Builds an InvokeResponse carrying a CommandStatusIB for each result.</summary>
    public static byte[] EncodeResponse(IReadOnlyList<CommandResult> results, bool suppressResponse = false)
    {
        var w = new TlvWriter();
        w.StartStructure(TlvTag.Anonymous);
        w.WriteBool(TlvTag.ContextSpecific(TagSuppressResponse), suppressResponse);

        w.StartArray(TlvTag.ContextSpecific(TagInvokeResponses));
        foreach (var res in results)
        {
            w.StartStructure(TlvTag.Anonymous);                          // InvokeResponseIB
            if (res.HasResponseData)
            {
                // CommandDataIB { 0: CommandPathIB, 1: CommandFields }
                w.StartStructure(TlvTag.ContextSpecific(TagCommandData));
                new CommandPath(res.Path.Endpoint, res.Path.Cluster, res.ResponseCommandId!.Value)
                    .Write(w, TlvTag.ContextSpecific(TagCommandPath));
                w.StartStructure(TlvTag.ContextSpecific(TagCommandFields));
                res.WriteResponseFields!(w);
                w.EndContainer();
                w.EndContainer();                                       // CommandDataIB
            }
            else
            {
                w.StartStructure(TlvTag.ContextSpecific(TagStatus));     // CommandStatusIB
                res.Path.Write(w, TlvTag.ContextSpecific(TagCsCommandPath));
                w.StartStructure(TlvTag.ContextSpecific(TagCsStatus));   // StatusIB
                w.WriteUInt(TlvTag.ContextSpecific(TagStatusCode), (byte)res.Status);
                w.EndContainer();                                       // StatusIB
                w.EndContainer();                                       // CommandStatusIB
            }
            w.EndContainer();                                           // InvokeResponseIB
        }
        w.EndContainer();                                               // InvokeResponses array

        w.WriteUInt(TlvTag.ContextSpecific(ImConstants.InteractionModelRevisionTag), ImConstants.InteractionModelRevision);
        w.EndContainer();
        return w.ToArray();
    }
}

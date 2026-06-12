using MatterDevice.Core.Tlv;

namespace MatterDevice.DataModel.InteractionModel;

/// <summary>One attribute write: the target path and the decoded value.</summary>
public sealed record AttributeWrite(AttributePath Path, object? Value);

/// <summary>The status of applying one attribute write.</summary>
public sealed record AttributeWriteResult(AttributePath Path, WriteStatus Status);

/// <summary>
/// WriteRequest / WriteResponse codecs (Matter Core Spec §10.6, §8.6–8.7). A WriteRequest carries
/// AttributeDataIBs (path + value); the WriteResponse returns an AttributeStatusIB per write.
/// </summary>
public static class WriteInteraction
{
    // WriteRequestMessage tags
    private const int TagSuppressResponse = 0;
    private const int TagTimedRequest = 1;
    private const int TagWriteRequests = 2;

    // WriteResponseMessage tags
    private const int TagWriteResponses = 0;

    // AttributeDataIB tags
    private const int TagPath = 1;
    private const int TagData = 2;

    // AttributeStatusIB / StatusIB tags
    private const int TagStatusPath = 0;
    private const int TagStatus = 1;
    private const int TagStatusCode = 0;

    public static IReadOnlyList<AttributeWrite> DecodeRequest(ReadOnlySpan<byte> tlv)
    {
        var writes = new List<AttributeWrite>();
        var r = new TlvReader(tlv);
        if (!r.Read() || !r.IsContainer) throw new FormatException("WriteRequest: expected a struct.");
        r.EnterContainer((ref TlvReader f) =>
        {
            if (f.TagNumber != TagWriteRequests || !f.IsContainer) return;
            f.EnterContainer((ref TlvReader dataIb) =>
            {
                if (!dataIb.IsContainer) return;
                AttributePath path = default;
                object? value = null;
                dataIb.EnterContainer((ref TlvReader g) =>
                {
                    if (g.TagNumber == TagPath && g.IsContainer) path = AttributePath.Read(ref g);
                    else if (g.TagNumber == TagData) value = InteractionDispatcher.ReadValue(ref g);
                });
                writes.Add(new AttributeWrite(path, value));
            });
        });
        return writes;
    }

    public static byte[] EncodeResponse(IReadOnlyList<AttributeWriteResult> results)
    {
        var w = new TlvWriter();
        w.StartStructure(TlvTag.Anonymous);
        w.StartArray(TlvTag.ContextSpecific(TagWriteResponses));
        foreach (var res in results)
        {
            w.StartStructure(TlvTag.Anonymous);                      // AttributeStatusIB
            res.Path.Write(w, TlvTag.ContextSpecific(TagStatusPath));
            w.StartStructure(TlvTag.ContextSpecific(TagStatus));     // StatusIB
            w.WriteUInt(TlvTag.ContextSpecific(TagStatusCode), (byte)res.Status);
            w.EndContainer();
            w.EndContainer();                                       // AttributeStatusIB
        }
        w.EndContainer();
        w.WriteUInt(TlvTag.ContextSpecific(ImConstants.InteractionModelRevisionTag), ImConstants.InteractionModelRevision);
        w.EndContainer();
        return w.ToArray();
    }

    /// <summary>Builds a WriteRequest for the given path/value writes (controller/test side).</summary>
    public static byte[] EncodeRequest(IReadOnlyList<(AttributePath Path, Action<TlvWriter, TlvTag> WriteData)> writes, bool suppressResponse = false, bool timed = false)
    {
        var w = new TlvWriter();
        w.StartStructure(TlvTag.Anonymous);
        w.WriteBool(TlvTag.ContextSpecific(TagSuppressResponse), suppressResponse);
        w.WriteBool(TlvTag.ContextSpecific(TagTimedRequest), timed);
        w.StartArray(TlvTag.ContextSpecific(TagWriteRequests));
        foreach (var (path, writeData) in writes)
        {
            w.StartStructure(TlvTag.Anonymous);                      // AttributeDataIB
            path.Write(w, TlvTag.ContextSpecific(TagPath));
            writeData(w, TlvTag.ContextSpecific(TagData));
            w.EndContainer();
        }
        w.EndContainer();
        w.WriteUInt(TlvTag.ContextSpecific(ImConstants.InteractionModelRevisionTag), ImConstants.InteractionModelRevision);
        w.EndContainer();
        return w.ToArray();
    }
}

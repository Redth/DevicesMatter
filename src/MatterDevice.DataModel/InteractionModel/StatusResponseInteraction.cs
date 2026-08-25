using MatterDevice.Core.Tlv;

namespace MatterDevice.DataModel.InteractionModel;

/// <summary>
/// StatusResponse (Matter Core Spec §10.6.2) — the one-field message a peer sends to acknowledge an
/// Interaction Model message it isn't otherwise replying to. It is what paces a chunked ReportData: the
/// device releases the next chunk only when the previous one is acked, so a controller harness that never
/// sends these will see exactly one chunk and then silence.
/// </summary>
public static class StatusResponseInteraction
{
    private const int TagStatus = 0;

    public static byte[] Encode(ImStatus status = ImStatus.Success)
    {
        var w = new TlvWriter();
        w.StartStructure(TlvTag.Anonymous)
            .WriteUInt(TlvTag.ContextSpecific(TagStatus), (byte)status)
            .WriteUInt(TlvTag.ContextSpecific(ImConstants.InteractionModelRevisionTag), ImConstants.InteractionModelRevision)
            .EndContainer();
        return w.ToArray();
    }

    public static ImStatus Decode(ReadOnlySpan<byte> tlv)
    {
        var status = ImStatus.Success;
        var r = new TlvReader(tlv);
        if (!r.Read() || !r.IsContainer) throw new FormatException("StatusResponse: expected a struct.");
        r.EnterContainer((ref TlvReader f) =>
        {
            if (f.TagNumber == TagStatus) status = (ImStatus)f.GetUInt();
        });
        return status;
    }
}

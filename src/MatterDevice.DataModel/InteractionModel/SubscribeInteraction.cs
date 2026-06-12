using MatterDevice.Core.Tlv;

namespace MatterDevice.DataModel.InteractionModel;

/// <summary>A decoded SubscribeRequest: the reporting interval bounds and the attribute paths to watch.</summary>
public sealed record SubscribeRequest(ushort MinIntervalFloor, ushort MaxIntervalCeiling, IReadOnlyList<AttributePath> Paths, bool KeepSubscriptions);

/// <summary>
/// SubscribeRequest / SubscribeResponse codecs (Matter Core Spec §10.6, §8.5). After a SubscribeRequest
/// the device sends priming ReportData then a SubscribeResponse carrying the subscription id and the
/// negotiated max interval; thereafter it reports on change and at least every max interval.
/// </summary>
public static class SubscribeInteraction
{
    // SubscribeRequestMessage tags
    private const int TagKeepSubscriptions = 0;
    private const int TagMinIntervalFloor = 1;
    private const int TagMaxIntervalCeiling = 2;
    private const int TagAttributeRequests = 3;

    // SubscribeResponseMessage tags
    private const int TagSubscriptionId = 0;
    private const int TagMaxInterval = 2;

    public static SubscribeRequest DecodeRequest(ReadOnlySpan<byte> tlv)
    {
        ushort minFloor = 0, maxCeiling = 0;
        var keep = false;
        var paths = new List<AttributePath>();

        var r = new TlvReader(tlv);
        if (!r.Read() || !r.IsContainer) throw new FormatException("SubscribeRequest: expected a struct.");
        r.EnterContainer((ref TlvReader f) =>
        {
            switch (f.TagNumber)
            {
                case TagKeepSubscriptions: keep = f.GetBool(); break;
                case TagMinIntervalFloor: minFloor = (ushort)f.GetUInt(); break;
                case TagMaxIntervalCeiling: maxCeiling = (ushort)f.GetUInt(); break;
                case TagAttributeRequests when f.IsContainer:
                    f.EnterContainer((ref TlvReader p) => { if (p.IsContainer) paths.Add(AttributePath.Read(ref p)); });
                    break;
            }
        });
        return new SubscribeRequest(minFloor, maxCeiling, paths, keep);
    }

    public static byte[] EncodeResponse(uint subscriptionId, ushort maxInterval)
    {
        var w = new TlvWriter();
        w.StartStructure(TlvTag.Anonymous)
            .WriteUInt(TlvTag.ContextSpecific(TagSubscriptionId), subscriptionId)
            .WriteUInt(TlvTag.ContextSpecific(TagMaxInterval), maxInterval)
            .WriteUInt(TlvTag.ContextSpecific(ImConstants.InteractionModelRevisionTag), ImConstants.InteractionModelRevision)
            .EndContainer();
        return w.ToArray();
    }
}

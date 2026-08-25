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
    private const int TagIsFabricFiltered = 4;

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

    /// <summary>
    /// Encodes a SubscribeRequest — the controller side of the exchange. The device itself never sends one;
    /// this exists so you can drive your own device from a test/controller harness (pair it with
    /// <see cref="StatusResponseInteraction"/> to ack the reports that come back).
    /// </summary>
    /// <param name="paths">Attribute paths to watch. Leave components null to wildcard, e.g.
    /// <c>new AttributePath(null, null, null)</c> subscribes to the whole node the way Apple Home does.</param>
    /// <param name="minIntervalFloor">Fastest reporting rate the controller will accept, in seconds.</param>
    /// <param name="maxIntervalCeiling">Slowest acceptable gap between reports, in seconds.</param>
    /// <param name="keepSubscriptions">Whether the device should keep this peer's existing subscriptions.</param>
    /// <param name="isFabricFiltered">Whether to return only fabric-scoped data visible to this fabric.</param>
    public static byte[] EncodeRequest(
        IReadOnlyList<AttributePath> paths,
        ushort minIntervalFloor = 0,
        ushort maxIntervalCeiling = 60,
        bool keepSubscriptions = false,
        bool isFabricFiltered = true)
    {
        var w = new TlvWriter();
        w.StartStructure(TlvTag.Anonymous)
            .WriteBool(TlvTag.ContextSpecific(TagKeepSubscriptions), keepSubscriptions)
            .WriteUInt(TlvTag.ContextSpecific(TagMinIntervalFloor), minIntervalFloor)
            .WriteUInt(TlvTag.ContextSpecific(TagMaxIntervalCeiling), maxIntervalCeiling);
        w.StartArray(TlvTag.ContextSpecific(TagAttributeRequests));
        foreach (var path in paths) path.Write(w, TlvTag.Anonymous);
        w.EndContainer();
        w.WriteBool(TlvTag.ContextSpecific(TagIsFabricFiltered), isFabricFiltered);
        w.WriteUInt(TlvTag.ContextSpecific(ImConstants.InteractionModelRevisionTag), ImConstants.InteractionModelRevision);
        w.EndContainer();
        return w.ToArray();
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

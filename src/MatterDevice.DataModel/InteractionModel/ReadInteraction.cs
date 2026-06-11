using MatterDevice.Core.Tlv;

namespace MatterDevice.DataModel.InteractionModel;

/// <summary>One attribute's reported value — its path plus a writer that emits the TLV data element.</summary>
public sealed record AttributeReport(AttributePath Path, Action<TlvWriter, TlvTag> WriteData, uint DataVersion = 1);

/// <summary>
/// ReadRequest / ReportData codecs (Matter Core Spec §10.6, §8.4–8.5). A ReadRequest lists the attribute
/// paths the controller wants; ReportData returns AttributeDataIBs with the values.
/// </summary>
public static class ReadInteraction
{
    // ReadRequestMessage tags
    private const int TagAttributeRequests = 0;
    private const int TagIsFabricFiltered = 3;

    // ReportDataMessage tags
    private const int TagAttributeReports = 1;
    private const int TagSuppressResponse = 4;

    // AttributeReportIB / AttributeDataIB tags
    private const int TagAttributeData = 1;     // within AttributeReportIB
    private const int TagDataVersion = 0;       // within AttributeDataIB
    private const int TagPath = 1;              // within AttributeDataIB
    private const int TagData = 2;              // within AttributeDataIB

    /// <summary>Builds a ReadRequest for the given attribute paths (controller/test side).</summary>
    public static byte[] EncodeRequest(IReadOnlyList<AttributePath> paths, bool isFabricFiltered = true)
    {
        var w = new TlvWriter();
        w.StartStructure(TlvTag.Anonymous);
        w.StartArray(TlvTag.ContextSpecific(TagAttributeRequests));
        foreach (var p in paths)
            p.Write(w, TlvTag.Anonymous); // array elements are anonymous
        w.EndContainer();
        w.WriteBool(TlvTag.ContextSpecific(TagIsFabricFiltered), isFabricFiltered);
        w.WriteUInt(TlvTag.ContextSpecific(ImConstants.InteractionModelRevisionTag), ImConstants.InteractionModelRevision);
        w.EndContainer();
        return w.ToArray();
    }

    /// <summary>Parses a ReadRequest, returning the requested attribute paths.</summary>
    public static IReadOnlyList<AttributePath> DecodeRequest(ReadOnlySpan<byte> tlv)
    {
        var paths = new List<AttributePath>();
        var r = new TlvReader(tlv);
        if (!r.Read() || !r.IsContainer) throw new FormatException("ReadRequest: expected a struct.");
        r.EnterContainer((ref TlvReader f) =>
        {
            if (f.TagNumber == TagAttributeRequests && f.IsContainer)
            {
                // array of AttributePathIB (anonymous list elements)
                f.EnterContainer((ref TlvReader item) =>
                {
                    if (item.IsContainer)
                        paths.Add(AttributePath.Read(ref item));
                });
            }
        });
        return paths;
    }

    /// <summary>Builds a ReportData message carrying the given attribute reports.</summary>
    public static byte[] EncodeReport(IReadOnlyList<AttributeReport> reports, bool suppressResponse = true)
    {
        var w = new TlvWriter();
        w.StartStructure(TlvTag.Anonymous);

        w.StartArray(TlvTag.ContextSpecific(TagAttributeReports));
        foreach (var rep in reports)
        {
            w.StartStructure(TlvTag.Anonymous);                         // AttributeReportIB
            w.StartStructure(TlvTag.ContextSpecific(TagAttributeData)); // AttributeDataIB
            w.WriteUInt(TlvTag.ContextSpecific(TagDataVersion), rep.DataVersion);
            rep.Path.Write(w, TlvTag.ContextSpecific(TagPath));
            rep.WriteData(w, TlvTag.ContextSpecific(TagData));
            w.EndContainer();                                           // AttributeDataIB
            w.EndContainer();                                           // AttributeReportIB
        }
        w.EndContainer();                                               // AttributeReports array

        w.WriteBool(TlvTag.ContextSpecific(TagSuppressResponse), suppressResponse);
        w.WriteUInt(TlvTag.ContextSpecific(ImConstants.InteractionModelRevisionTag), ImConstants.InteractionModelRevision);
        w.EndContainer();
        return w.ToArray();
    }
}

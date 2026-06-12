using System.Net;

namespace MatterDevice.Commissioning.Discovery;

/// <summary>
/// DNS-SD advertising for a commissioned (operational) Matter node (Matter Core Spec §4.3.1): the
/// <c>_matter._tcp.local</c> service with the operational instance name
/// <c>&lt;compressedFabricId&gt;-&lt;nodeId&gt;</c>, the <c>_I&lt;compressedFabricId&gt;</c> subtype, SRV/TXT, and host
/// addresses. A controller resolves this after commissioning to open a CASE session.
/// </summary>
public sealed class MatterOperationalService : IMdnsAdvertisement
{
    public const string ServiceType = "_matter._tcp.local";

    public required string CompressedFabricIdHex { get; init; } // 16 uppercase hex
    public required string NodeIdHex { get; init; }             // 16 uppercase hex
    public required string HostName { get; init; }
    public ushort Port { get; init; } = 5540;
    public IReadOnlyList<IPAddress> Addresses { get; init; } = [];

    public string InstanceName => $"{CompressedFabricIdHex}-{NodeIdHex}.{ServiceType}";
    private string CompressedFabricSubtype => $"_I{CompressedFabricIdHex}._sub.{ServiceType}";

    public IEnumerable<string> QueryableNames() =>
        [ServiceType, InstanceName, HostName, CompressedFabricSubtype];

    public IReadOnlyList<DnsRecord> BuildRecords()
    {
        var records = new List<DnsRecord>
        {
            new PtrRecord(ServiceType, InstanceName),
            new PtrRecord(CompressedFabricSubtype, InstanceName),
            new SrvRecord(InstanceName, HostName, Port),
            // Common TXT keys (MRP timings); all optional.
            new TxtRecord(InstanceName, ["SII=500", "SAI=300", "SAT=4000", "T=0", "ICD=0"]),
        };
        foreach (var addr in Addresses)
            records.Add(new AddressRecord(HostName, addr));
        return records;
    }
}

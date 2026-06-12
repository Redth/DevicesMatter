using System.Globalization;
using System.Net;
using System.Security.Cryptography;

namespace MatterDevice.Commissioning.Discovery;

/// <summary>
/// Describes a commissionable Matter node for DNS-SD advertising (Matter Core Spec §4.3) and builds its
/// record set: the <c>_matterc._udp.local</c> service PTR, the <c>_L</c>/<c>_S</c> discriminator subtype
/// PTRs, SRV, TXT (<c>D</c>, <c>CM</c>, <c>VP</c>, …) and the host A/AAAA records.
/// </summary>
public sealed class MatterCommissionableService : IMdnsAdvertisement
{
    public const string ServiceType = "_matterc._udp.local";

    public ushort Discriminator { get; init; }
    public ushort VendorId { get; init; }
    public ushort ProductId { get; init; }

    /// <summary>0 = not in commissioning mode, 1 = standard, 2 = enhanced.</summary>
    public byte CommissioningMode { get; init; } = 1;

    public string? DeviceName { get; init; }
    public ushort Port { get; init; } = 5540;

    /// <summary>Random 64-bit instance id (16 hex chars), regenerated per commissioning session.</summary>
    public string InstanceId { get; init; } = RandomNumberGenerator.GetHexString(16, lowercase: false);

    /// <summary>Host label (defaults to a random 64-bit hex, like CHIP's MAC/EUI-64 host name).</summary>
    public string HostName { get; init; } = RandomNumberGenerator.GetHexString(16, lowercase: false) + ".local";

    public IReadOnlyList<IPAddress> Addresses { get; init; } = [];

    public string InstanceName => $"{InstanceId}.{ServiceType}";

    public IEnumerable<string> QueryableNames()
    {
        var shortDisc = (Discriminator >> 8) & 0x0F;
        return
        [
            ServiceType, InstanceName, HostName,
            $"_L{Discriminator}._sub.{ServiceType}",
            $"_S{shortDisc}._sub.{ServiceType}",
            $"_V{VendorId}._sub.{ServiceType}",
            $"_CM._sub.{ServiceType}",
        ];
    }

    /// <summary>The TXT key/value pairs for this commissionable node (D and CM are mandatory).</summary>
    public IReadOnlyList<string> TxtEntries()
    {
        var entries = new List<string>
        {
            $"D={Discriminator.ToString(CultureInfo.InvariantCulture)}",
            $"CM={CommissioningMode.ToString(CultureInfo.InvariantCulture)}",
            $"VP={VendorId.ToString(CultureInfo.InvariantCulture)}+{ProductId.ToString(CultureInfo.InvariantCulture)}",
        };
        if (!string.IsNullOrEmpty(DeviceName))
            entries.Add($"DN={DeviceName}");
        return entries;
    }

    /// <summary>Builds the full DNS-SD answer set advertised for this node.</summary>
    public IReadOnlyList<DnsRecord> BuildRecords()
    {
        var shortDisc = (Discriminator >> 8) & 0x0F;
        var records = new List<DnsRecord>
        {
            // service + subtype pointers (shared records — no cache-flush)
            new PtrRecord(ServiceType, InstanceName),
            new PtrRecord($"_L{Discriminator}._sub.{ServiceType}", InstanceName),
            new PtrRecord($"_S{shortDisc}._sub.{ServiceType}", InstanceName),
            new PtrRecord($"_V{VendorId}._sub.{ServiceType}", InstanceName),
            new PtrRecord($"_CM._sub.{ServiceType}", InstanceName),
            // SRV + TXT for the instance
            new SrvRecord(InstanceName, HostName, Port),
            new TxtRecord(InstanceName, TxtEntries()),
        };
        foreach (var addr in Addresses)
            records.Add(new AddressRecord(HostName, addr));
        return records;
    }
}

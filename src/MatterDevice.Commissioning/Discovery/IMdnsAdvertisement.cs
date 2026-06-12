namespace MatterDevice.Commissioning.Discovery;

/// <summary>A DNS-SD advertisement the responder can publish and answer queries for.</summary>
public interface IMdnsAdvertisement
{
    /// <summary>The DNS names a query may target to elicit this advertisement (service, subtypes, instance, host).</summary>
    IEnumerable<string> QueryableNames();

    /// <summary>The full record set to return.</summary>
    IReadOnlyList<DnsRecord> BuildRecords();
}

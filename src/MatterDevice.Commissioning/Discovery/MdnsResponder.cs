using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MatterDevice.Commissioning.Discovery;

/// <summary>
/// A minimal multicast DNS (RFC 6762) responder that advertises one Matter commissionable service. It
/// announces the record set on start and answers queries that match the service, its subtypes, the
/// instance, or the host. Sufficient to make the node discoverable on the LAN by a Matter commissioner.
/// </summary>
/// <remarks>
/// Intentionally minimal for the spike: IPv4 multicast (224.0.0.251:5353), no name compression on
/// output, no known-answer suppression, single service. Robust multi-interface / IPv6 / conflict
/// handling is follow-on work (see <c>docs/00-feasibility.md</c>).
/// </remarks>
public sealed class MdnsResponder : IAsyncDisposable
{
    private static readonly IPAddress MulticastV4 = IPAddress.Parse("224.0.0.251");
    private const int MdnsPort = 5353;

    private readonly MatterCommissionableService _service;
    private readonly ILogger _log;
    private readonly UdpClient _udp;
    private readonly List<IMdnsAdvertisement> _ads = [];
    private readonly Lock _gate = new();

    public MdnsResponder(MatterCommissionableService service, ILogger? logger = null)
    {
        _service = service;
        _log = logger ?? NullLogger.Instance;

        _udp = new UdpClient(AddressFamily.InterNetwork);
        _udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _udp.Client.Bind(new IPEndPoint(IPAddress.Any, MdnsPort));
        _udp.JoinMulticastGroup(MulticastV4);
        _udp.MulticastLoopback = true;

        _ads.Add(service);
    }

    /// <summary>Adds a service to advertise (e.g. the operational service after commissioning) and announces it.</summary>
    public async Task AdvertiseAsync(IMdnsAdvertisement advertisement)
    {
        lock (_gate) _ads.Add(advertisement);
        await SendAsync(advertisement.BuildRecords()).ConfigureAwait(false);
        _log.LogInformation("mDNS now advertising {Count} service(s)", _ads.Count);
    }

    /// <summary>Announces all current services (gratuitous response).</summary>
    public async Task AnnounceAsync()
    {
        foreach (var ad in Snapshot())
            await SendAsync(ad.BuildRecords()).ConfigureAwait(false);
        _log.LogInformation("mDNS announced {Instance}", _service.InstanceName);
    }

    /// <summary>Listens for queries and answers those matching any advertised service, until cancelled.</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        await AnnounceAsync().ConfigureAwait(false);
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult rx;
            try { rx = await _udp.ReceiveAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }

            try
            {
                var msg = DnsMessage.Parse(rx.Buffer);
                if (msg.IsResponse)
                    continue;
                var questionNames = msg.Questions.Select(q => q.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
                foreach (var ad in Snapshot())
                {
                    if (ad.QueryableNames().Any(questionNames.Contains))
                        await SendAsync(ad.BuildRecords()).ConfigureAwait(false);
                }
            }
            catch (Exception ex) { _log.LogTrace(ex, "Ignoring malformed mDNS packet"); }
        }
    }

    private async Task SendAsync(IReadOnlyList<DnsRecord> records)
    {
        var packet = DnsMessage.BuildResponse(records);
        await _udp.SendAsync(packet, packet.Length, new IPEndPoint(MulticastV4, MdnsPort)).ConfigureAwait(false);
    }

    private List<IMdnsAdvertisement> Snapshot()
    {
        lock (_gate) return [.. _ads];
    }

    /// <summary>Local non-loopback IPv4 addresses, for the A records.</summary>
    public static IReadOnlyList<IPAddress> LocalIPv4Addresses()
    {
        return Dns.GetHostAddresses(Dns.GetHostName())
            .Where(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a))
            .ToList();
    }

    public ValueTask DisposeAsync()
    {
        try { _udp.DropMulticastGroup(MulticastV4); } catch { /* socket may be closed */ }
        _udp.Dispose();
        return ValueTask.CompletedTask;
    }
}

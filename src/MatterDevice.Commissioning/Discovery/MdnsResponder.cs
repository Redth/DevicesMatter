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
    private readonly HashSet<string> _ourNames;

    public MdnsResponder(MatterCommissionableService service, ILogger? logger = null)
    {
        _service = service;
        _log = logger ?? NullLogger.Instance;

        _udp = new UdpClient(AddressFamily.InterNetwork);
        _udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _udp.Client.Bind(new IPEndPoint(IPAddress.Any, MdnsPort));
        _udp.JoinMulticastGroup(MulticastV4);
        _udp.MulticastLoopback = true;

        var shortDisc = (service.Discriminator >> 8) & 0x0F;
        _ourNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            MatterCommissionableService.ServiceType,
            service.InstanceName,
            service.HostName,
            $"_L{service.Discriminator}._sub.{MatterCommissionableService.ServiceType}",
            $"_S{shortDisc}._sub.{MatterCommissionableService.ServiceType}",
            $"_V{service.VendorId}._sub.{MatterCommissionableService.ServiceType}",
            $"_CM._sub.{MatterCommissionableService.ServiceType}",
        };
    }

    /// <summary>Announces the service (gratuitous response) — call a couple of times on startup.</summary>
    public async Task AnnounceAsync()
    {
        var packet = DnsMessage.BuildResponse(_service.BuildRecords());
        await _udp.SendAsync(packet, packet.Length, new IPEndPoint(MulticastV4, MdnsPort)).ConfigureAwait(false);
        _log.LogInformation("mDNS announced {Instance} ({Count} records)", _service.InstanceName, _service.BuildRecords().Count);
    }

    /// <summary>Listens for queries and answers those matching our names, until cancelled.</summary>
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
                if (msg.Questions.Any(q => _ourNames.Contains(q.Name)))
                {
                    var packet = DnsMessage.BuildResponse(_service.BuildRecords());
                    await _udp.SendAsync(packet, packet.Length, new IPEndPoint(MulticastV4, MdnsPort)).ConfigureAwait(false);
                    _log.LogDebug("mDNS answered query for {Names}", string.Join(",", msg.Questions.Select(q => q.Name)));
                }
            }
            catch (Exception ex) { _log.LogTrace(ex, "Ignoring malformed mDNS packet"); }
        }
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

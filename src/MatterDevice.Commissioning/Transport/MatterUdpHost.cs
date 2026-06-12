using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MatterDevice.Commissioning.Transport;

/// <summary>
/// Binds the Matter UDP port (5540) and pumps datagrams through a <see cref="MatterDeviceNode"/>: every
/// inbound packet is handed to <see cref="MatterDeviceNode.ProcessDatagram"/> and each response is sent
/// back to the sender. This is the thin socket layer over the protocol orchestrator.
/// </summary>
public sealed class MatterUdpHost : IAsyncDisposable
{
    public const int DefaultPort = 5540;

    private readonly MatterDeviceNode _node;
    private readonly ILogger _log;
    private readonly UdpClient _udp;

    public MatterUdpHost(MatterDeviceNode node, int port = DefaultPort, ILogger? logger = null)
    {
        _node = node;
        _log = logger ?? NullLogger.Instance;
        _udp = new UdpClient(AddressFamily.InterNetwork);
        _udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _udp.Client.Bind(new IPEndPoint(IPAddress.Any, port));

        // Let the node push asynchronous subscription reports back to a peer endpoint.
        _node.SendDatagram = async (peer, datagram, token) =>
            await _udp.SendAsync(datagram, datagram.Length, (IPEndPoint)peer).ConfigureAwait(false);
    }

    public int BoundPort => ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;

    public async Task RunAsync(CancellationToken ct)
    {
        _log.LogInformation("Matter UDP host listening on port {Port}", BoundPort);
        var heartbeat = RunHeartbeatAsync(ct);
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult rx;
            try { rx = await _udp.ReceiveAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }

            try
            {
                foreach (var response in _node.ProcessDatagram(rx.Buffer, rx.RemoteEndPoint))
                    await _udp.SendAsync(response, response.Length, rx.RemoteEndPoint).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Failed to process datagram from {Peer}", rx.RemoteEndPoint);
            }
        }
        await heartbeat.ConfigureAwait(false);
    }

    /// <summary>Periodically nudges the node to emit subscription heartbeat reports.</summary>
    private async Task RunHeartbeatAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
                await _node.TickAsync(ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { /* shutting down */ }
    }

    public ValueTask DisposeAsync()
    {
        _udp.Dispose();
        return ValueTask.CompletedTask;
    }
}

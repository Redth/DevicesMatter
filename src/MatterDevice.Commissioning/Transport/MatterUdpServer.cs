using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using MatterDevice.Commissioning.Pase;
using MatterDevice.Core.Messaging;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MatterDevice.Commissioning.Transport;

/// <summary>
/// A minimal Matter message transport over UDP (default port 5540) that drives a <see cref="PaseResponder"/>
/// through commissioning. It parses the unsecured-session framing, runs the Secure Channel exchange
/// (PBKDFParamRequest → … → StatusReport), and piggybacks MRP acknowledgements onto its replies.
/// </summary>
/// <remarks>
/// This is the spike's on-the-wire integration: it proves the device can receive real Matter datagrams,
/// complete PASE, and establish session keys. Not yet implemented: full MRP retransmission/dedup, the
/// encrypted (post-PASE) session path, and CASE — see <c>docs/00-feasibility.md</c>.
/// </remarks>
public sealed class MatterUdpServer : IAsyncDisposable
{
    public const int DefaultPort = 5540;

    private readonly Func<PaseResponder> _responderFactory;
    private readonly ILogger _log;
    private readonly UdpClient _udp;
    private uint _messageCounter;
    private PaseResponder? _activeResponder;

    /// <summary>Raised when a PASE session is successfully established.</summary>
    public event Action<PaseSession>? SessionEstablished;

    public MatterUdpServer(Func<PaseResponder> responderFactory, int port = DefaultPort, ILogger? logger = null)
    {
        _responderFactory = responderFactory;
        _log = logger ?? NullLogger.Instance;
        _udp = new UdpClient(AddressFamily.InterNetwork);
        _udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _udp.Client.Bind(new IPEndPoint(IPAddress.Any, port));
        // Random non-zero initial counter (Core Spec §4.6.6).
        _messageCounter = (BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4)) >> 4) + 1;
    }

    public int BoundPort => ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;

    /// <summary>Receives and processes datagrams until <paramref name="ct"/> is cancelled.</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        _log.LogInformation("Matter UDP server listening on port {Port}", BoundPort);
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult rx;
            try { rx = await _udp.ReceiveAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }

            try { await HandleDatagramAsync(rx.Buffer, rx.RemoteEndPoint).ConfigureAwait(false); }
            catch (Exception ex) { _log.LogWarning(ex, "Failed to process datagram from {Peer}", rx.RemoteEndPoint); }
        }
    }

    private async Task HandleDatagramAsync(byte[] data, IPEndPoint peer)
    {
        var msg = MatterMessage.Decode(data);
        if (msg.ProtocolId != MatterProtocolId.SecureChannel)
        {
            _log.LogDebug("Ignoring non-SecureChannel protocol {Protocol}", msg.ProtocolId);
            return;
        }

        switch ((SecureChannelOpcode)msg.Opcode)
        {
            case SecureChannelOpcode.PbkdfParamRequest:
                _activeResponder = _responderFactory();
                _log.LogInformation("← PBKDFParamRequest (exchange {Exchange})", msg.ExchangeId);
                var resp = _activeResponder.OnPbkdfParamRequest(msg.Payload);
                await ReplyAsync(msg, peer, SecureChannelOpcode.PbkdfParamResponse, resp.Encode(), requiresAck: true);
                break;

            case SecureChannelOpcode.PasePake1:
                if (_activeResponder is null) { _log.LogWarning("Pake1 with no active PASE"); return; }
                _log.LogInformation("← PASE Pake1");
                var pake2 = _activeResponder.OnPake1(msg.Payload);
                await ReplyAsync(msg, peer, SecureChannelOpcode.PasePake2, pake2.Encode(), requiresAck: true);
                break;

            case SecureChannelOpcode.PasePake3:
                if (_activeResponder is null) { _log.LogWarning("Pake3 with no active PASE"); return; }
                _log.LogInformation("← PASE Pake3");
                var session = _activeResponder.OnPake3(msg.Payload);
                if (session is not null)
                {
                    await ReplyAsync(msg, peer, SecureChannelOpcode.StatusReport,
                        StatusReport.SessionEstablished().Encode(), requiresAck: false);
                    _log.LogInformation("✓ PASE session established (peer session {Peer})", session.PeerSessionId);
                    SessionEstablished?.Invoke(session);
                }
                else
                {
                    await ReplyAsync(msg, peer, SecureChannelOpcode.StatusReport,
                        StatusReport.Failure(SecureChannelStatusCode.InvalidParameter).Encode(), requiresAck: false);
                    _log.LogWarning("✗ PASE confirmation failed");
                }
                _activeResponder = null;
                break;

            case SecureChannelOpcode.StandaloneAck:
                // peer acked one of our reliable messages — nothing further to do in the spike
                break;

            default:
                _log.LogDebug("Unhandled Secure Channel opcode 0x{Opcode:X2}", msg.Opcode);
                break;
        }
    }

    private async Task ReplyAsync(MatterMessage request, IPEndPoint peer, SecureChannelOpcode opcode, byte[] payload, bool requiresAck)
    {
        var reply = new MatterMessage
        {
            SessionId = 0,
            SecurityFlags = 0,
            MessageCounter = NextCounter(),
            IsInitiator = false,
            IsAck = request.RequiresAck,
            AckedMessageCounter = request.RequiresAck ? request.MessageCounter : null,
            RequiresAck = requiresAck,
            Opcode = (byte)opcode,
            ExchangeId = request.ExchangeId,
            ProtocolId = MatterProtocolId.SecureChannel,
            Payload = payload,
        };
        var bytes = reply.Encode();
        await _udp.SendAsync(bytes, bytes.Length, peer).ConfigureAwait(false);
        _log.LogInformation("→ {Opcode} ({Len} bytes)", opcode, bytes.Length);
    }

    private uint NextCounter() => _messageCounter++;

    public ValueTask DisposeAsync()
    {
        _udp.Dispose();
        return ValueTask.CompletedTask;
    }
}

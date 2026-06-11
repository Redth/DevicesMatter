using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using MatterDevice.Commissioning.Pase;
using MatterDevice.Commissioning.Transport;
using MatterDevice.Core.Messaging;

namespace MatterDevice.Tests;

/// <summary>
/// Drives the <see cref="MatterUdpServer"/> over a real loopback UDP socket with a commissioner that
/// sends the five PASE messages as actual Matter datagrams. This proves the on-the-wire path — message
/// framing, MRP acks, and PASE — end to end, the closest stand-in for a live controller available
/// without one on the network.
/// </summary>
public class UdpCommissioningTests
{
    private const uint Passcode = 20202021;

    [Fact]
    public async Task Pase_completes_over_loopback_udp()
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        const int iterations = 1000;

        await using var server = new MatterUdpServer(
            () => new PaseResponder(Passcode, salt, iterations, localSessionId: 0x3030), port: 0);

        PaseSession? established = null;
        server.SessionEstablished += s => established = s;

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var serverTask = server.RunAsync(cts.Token);

        var prover = new TestProver(Passcode);
        using var client = new UdpClient();
        client.Connect(IPAddress.Loopback, server.BoundPort);

        ushort exchangeId = 0x7777;
        uint counter = 100;

        // 1. PBKDFParamRequest → PBKDFParamResponse
        var reqBytes = prover.BuildPbkdfParamRequest();
        var resp = await SendReceiveAsync(client, exchangeId, counter++, SecureChannelOpcode.PbkdfParamRequest, reqBytes, cts.Token);
        Assert.Equal((byte)SecureChannelOpcode.PbkdfParamResponse, resp.Opcode);
        prover.OnPbkdfParamResponse(reqBytes, resp.Payload);

        // 2. Pake1 → Pake2
        var pake2 = await SendReceiveAsync(client, exchangeId, counter++, SecureChannelOpcode.PasePake1, prover.BuildPake1(), cts.Token);
        Assert.Equal((byte)SecureChannelOpcode.PasePake2, pake2.Opcode);

        // 3. Pake3 → StatusReport(success)
        var pake3Bytes = prover.OnPake2BuildPake3(pake2.Payload);
        var status = await SendReceiveAsync(client, exchangeId, counter, SecureChannelOpcode.PasePake3, pake3Bytes, cts.Token);
        Assert.Equal((byte)SecureChannelOpcode.StatusReport, status.Opcode);

        var report = StatusReport.Decode(status.Payload);
        Assert.Equal(GeneralStatusCode.Success, report.GeneralStatus);
        Assert.Equal((ushort)SecureChannelStatusCode.SessionEstablishmentSuccess, report.ProtocolCode);

        // The device raised the session and both sides agree on the keys.
        Assert.NotNull(established);
        Assert.NotNull(prover.SessionKeys);
        Assert.Equal(Convert.ToHexString(prover.SessionKeys!.Value.I2R), Convert.ToHexString(established!.I2RKey));
        Assert.Equal(Convert.ToHexString(prover.SessionKeys.Value.Attest), Convert.ToHexString(established.AttestationChallenge));

        cts.Cancel();
        try { await serverTask; } catch (OperationCanceledException) { }
    }

    private static async Task<MatterMessage> SendReceiveAsync(
        UdpClient client, ushort exchangeId, uint counter, SecureChannelOpcode opcode, byte[] payload, CancellationToken ct)
    {
        var msg = new MatterMessage
        {
            SessionId = 0,
            MessageCounter = counter,
            SourceNodeId = 0, // unsecured-session commissioner
            IsInitiator = true,
            RequiresAck = true,
            Opcode = (byte)opcode,
            ExchangeId = exchangeId,
            ProtocolId = MatterProtocolId.SecureChannel,
            Payload = payload,
        };
        var bytes = msg.Encode();
        await client.SendAsync(bytes, bytes.Length).ConfigureAwait(false);

        var rx = await client.ReceiveAsync(ct).ConfigureAwait(false);
        return MatterMessage.Decode(rx.Buffer);
    }
}

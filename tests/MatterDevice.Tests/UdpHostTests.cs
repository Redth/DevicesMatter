using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using MatterDevice.Commissioning;
using MatterDevice.Commissioning.OperationalCredentials;
using MatterDevice.Commissioning.Pase;
using MatterDevice.Commissioning.Transport;
using MatterDevice.Core.Crypto;
using MatterDevice.Core.Messaging;
using MatterDevice.DataModel;

namespace MatterDevice.Tests;

/// <summary>
/// Drives the <see cref="MatterDeviceNode"/> through the <see cref="MatterUdpHost"/> over a real loopback
/// UDP socket, confirming the socket pump + orchestrator complete a PASE handshake (and establish an
/// encrypted session) exactly as a controller on the LAN would.
/// </summary>
public class UdpHostTests
{
    [Fact]
    public async Task Pase_completes_over_udp_through_the_orchestrator()
    {
        const uint passcode = 20202021;
        var node = new Node();
        node.AddEndpoint(0, DeviceType.RootNode);

        var device = new MatterDeviceNode(new MatterDeviceOptions
        {
            Passcode = passcode,
            PaseSalt = RandomNumberGenerator.GetBytes(16),
            Attestation = new DeviceAttestationProvider(P256KeyPair.Generate(),
                RandomNumberGenerator.GetBytes(64), RandomNumberGenerator.GetBytes(64), RandomNumberGenerator.GetBytes(128)),
            DataModel = node,
        });

        await using var host = new MatterUdpHost(device, port: 0);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var hostTask = host.RunAsync(cts.Token);

        var prover = new TestProver(passcode);
        using var client = new UdpClient();
        client.Connect(IPAddress.Loopback, host.BoundPort);

        ushort exchange = 0x6001;
        uint counter = 50;

        var reqBytes = prover.BuildPbkdfParamRequest();
        var resp = await Exchange(client, exchange, counter++, SecureChannelOpcode.PbkdfParamRequest, reqBytes, cts.Token);
        Assert.Equal((byte)SecureChannelOpcode.PbkdfParamResponse, resp.Opcode);
        prover.OnPbkdfParamResponse(reqBytes, resp.Payload);

        var pake2 = await Exchange(client, exchange, counter++, SecureChannelOpcode.PasePake1, prover.BuildPake1(), cts.Token);
        Assert.Equal((byte)SecureChannelOpcode.PasePake2, pake2.Opcode);

        var status = await Exchange(client, exchange, counter, SecureChannelOpcode.PasePake3, prover.OnPake2BuildPake3(pake2.Payload), cts.Token);
        Assert.Equal((byte)SecureChannelOpcode.StatusReport, status.Opcode);
        Assert.Equal(SecureChannelStatusCode.SessionEstablishmentSuccess, (SecureChannelStatusCode)StatusReport.Decode(status.Payload).ProtocolCode);

        // the device has a live encrypted session
        Assert.Single(device.Sessions);

        cts.Cancel();
        try { await hostTask; } catch (OperationCanceledException) { }
    }

    private static async Task<MatterMessage> Exchange(UdpClient client, ushort exchange, uint counter, SecureChannelOpcode opcode, byte[] payload, CancellationToken ct)
    {
        var msg = new MatterMessage
        {
            SessionId = 0, MessageCounter = counter, SourceNodeId = 0,
            IsInitiator = true, RequiresAck = true,
            Opcode = (byte)opcode, ExchangeId = exchange, ProtocolId = MatterProtocolId.SecureChannel, Payload = payload,
        };
        var bytes = msg.Encode();
        await client.SendAsync(bytes, bytes.Length).ConfigureAwait(false);
        var rx = await client.ReceiveAsync(ct).ConfigureAwait(false);
        return MatterMessage.Decode(rx.Buffer);
    }
}

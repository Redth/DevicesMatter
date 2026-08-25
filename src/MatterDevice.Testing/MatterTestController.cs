using System.Security.Cryptography;
using MatterDevice.Commissioning;
using MatterDevice.Commissioning.Case;
using MatterDevice.Commissioning.OperationalCredentials;
using MatterDevice.Commissioning.Pase;
using MatterDevice.Core.Credentials;
using MatterDevice.Core.Crypto;
using MatterDevice.Core.Messaging;
using MatterDevice.Core.Tlv;
using MatterDevice.DataModel.InteractionModel;

namespace MatterDevice.Testing;

/// <summary>
/// An in-process controller for testing your own <see cref="MatterDeviceNode"/>: it commissions the device
/// over the real wire format (PASE → attestation/CSR → AddNOC → CASE) and then speaks the Interaction Model
/// to it, so you can assert what a real ecosystem controller would actually observe.
/// <para>
/// The important part is <see cref="ReceiveReportAsync"/>. A device's reports are chunked and
/// flow-controlled — the next chunk is only released when the peer acks the previous one — so a naive
/// harness that reads one datagram sees a truncated snapshot and concludes reporting works when it doesn't.
/// This controller acks each chunk and returns the fully reassembled report.
/// </para>
/// </summary>
/// <example>
/// <code>
/// var controller = MatterTestController.Commission(device);
/// controller.Subscribe([new AttributePath(null, null, null)]);   // wildcard, like Apple Home
/// thermostat.LocalTemperatureCentiC = 2500;                      // device-side change
/// var report = await controller.ReceiveReportAsync();
/// Assert.Contains(report, a => a.Path.Attribute == ThermostatCluster.LocalTemperatureId);
/// </code>
/// </example>
public sealed class MatterTestController
{
    /// <summary>The passcode <see cref="Commission"/> uses when the device is built by
    /// <see cref="MatterTestDevice"/> or configured with the same default.</summary>
    public const uint DefaultPasscode = 20202021;

    /// <summary>IPv6 minimum MTU. A Matter message is a single datagram, so anything larger is liable to be
    /// dropped in transit rather than delivered.</summary>
    public const int UdpMtu = 1280;

    private readonly MatterDeviceNode _device;
    private readonly object _peer = new(); // opaque transport handle the device stamps onto the session
    private readonly Queue<byte[]> _pushed = new();
    private readonly List<int> _datagramSizes = [];
    private readonly Lock _pushGate = new();

    private ushort _exchangeId = 0x5000;
    private uint _counter = 1;
    private ushort _sessionId;
    private byte[] _encryptKey = [], _decryptKey = [];
    private ulong _nonceNodeId;

    /// <summary>The controller's operational node id on the commissioned fabric.</summary>
    public ulong ControllerNodeId { get; private init; }

    /// <summary>The device's operational node id on the commissioned fabric.</summary>
    public ulong DeviceNodeId { get; private init; }

    private MatterTestController(MatterDeviceNode device) => _device = device;

    /// <summary>
    /// Drives a full commissioning against <paramref name="device"/> and returns a controller holding an
    /// open operational (CASE) session. The device must have been constructed with
    /// <paramref name="passcode"/>.
    /// </summary>
    public static MatterTestController Commission(
        MatterDeviceNode device,
        uint passcode = DefaultPasscode,
        ulong fabricId = 0xFAB000000000001D,
        ulong deviceNodeId = 0x00000000DEDEDEDE,
        ulong controllerNodeId = 0x000000001234ABCD)
    {
        var controller = new MatterTestController(device)
        {
            ControllerNodeId = controllerNodeId,
            DeviceNodeId = deviceNodeId,
        };
        controller.CaptureOutboundDatagrams();

        // ---- PASE ----
        var prover = new PaseInitiator(passcode);
        var request = prover.BuildPbkdfParamRequest();
        var pbkdfResponse = controller.SendUnsecured(SecureChannelOpcode.PbkdfParamRequest, request);
        prover.OnPbkdfParamResponse(request, pbkdfResponse.Payload);
        var paseSessionId = PaseMessages.PbkdfParamResponse.Decode(pbkdfResponse.Payload).ResponderSessionId;

        var pake2 = controller.SendUnsecured(SecureChannelOpcode.PasePake1, prover.BuildPake1());
        controller.SendUnsecured(SecureChannelOpcode.PasePake3, prover.OnPake2BuildPake3(pake2.Payload));
        var (i2r, r2i, _) = prover.SessionKeys!.Value;
        controller.OpenSecure(paseSessionId, encryptKey: i2r, decryptKey: r2i);

        // ---- attestation + CSR over PASE ----
        controller.InvokeOpCreds(0x00, w => w.WriteBytes(TlvTag.ContextSpecific(0), RandomNumberGenerator.GetBytes(32)));
        var csrResponse = controller.InvokeOpCreds(0x04, w => w.WriteBytes(TlvTag.ContextSpecific(0), RandomNumberGenerator.GetBytes(32)));
        var nocsr = OpCredsMessages.DecodeNocsrElements(ReadResponseField(csrResponse, fieldTag: 0));
        var devicePublicKey = P256KeyPair.PublicKeyFromCsr(nocsr.Csr);

        // ---- install root + NOC ----
        var rootKey = P256KeyPair.Generate();
        var root = Core.Credentials.OperationalCredentials.CreateRootCertificate(rootKey, 0xCACACACA00000001);
        var deviceNoc = Core.Credentials.OperationalCredentials.CreateNodeCertificate(rootKey, root, devicePublicKey, fabricId, deviceNodeId);
        var ipk = RandomNumberGenerator.GetBytes(16);
        controller.InvokeOpCreds(0x0B, w => w.WriteBytes(TlvTag.ContextSpecific(0), root.Encode()));
        controller.InvokeOpCreds(0x06, w =>
        {
            w.WriteBytes(TlvTag.ContextSpecific(0), deviceNoc.Encode());
            w.WriteBytes(TlvTag.ContextSpecific(2), ipk);
        });

        // ---- CASE ----
        var controllerKey = P256KeyPair.Generate();
        var controllerNoc = Core.Credentials.OperationalCredentials.CreateNodeCertificate(rootKey, root, controllerKey, fabricId, controllerNodeId);
        var caseInitiator = new CaseInitiator(root, ipk, fabricId, deviceNodeId, controllerNoc, controllerKey, 0xB2B2);
        var sigma2 = controller.SendUnsecured(SecureChannelOpcode.CaseSigma1, caseInitiator.BuildSigma1());
        var responderSessionId = CaseMessages.Sigma2.Decode(sigma2.Payload).ResponderSessionId;
        controller.SendUnsecured(SecureChannelOpcode.CaseSigma3, caseInitiator.OnSigma2BuildSigma3(sigma2.Payload));

        var (caseI2r, caseR2i, _) = caseInitiator.SessionKeys!.Value;
        controller.OpenSecure(responderSessionId, encryptKey: caseI2r, decryptKey: caseR2i, nonceNodeId: controllerNodeId);
        controller._pushed.Clear(); // commissioning chatter isn't a report
        return controller;
    }

    /// <summary>Reads attributes, following any chunking, and returns everything reported.</summary>
    public IReadOnlyList<ReadInteraction.ReportedAttribute> Read(params AttributePath[] paths)
    {
        var first = SendSecure(ImOpcode.ReadRequest, ReadInteraction.EncodeRequest(paths));
        return DrainChunks(first);
    }

    /// <summary>Subscribes and returns the priming report. Later changes arrive via
    /// <see cref="ReceiveReportAsync"/>.</summary>
    public IReadOnlyList<ReadInteraction.ReportedAttribute> Subscribe(
        IReadOnlyList<AttributePath> paths, ushort maxIntervalCeiling = 60, ushort minIntervalFloor = 0)
    {
        var payload = SubscribeInteraction.EncodeRequest(paths, minIntervalFloor, maxIntervalCeiling);
        var first = SendSecure(ImOpcode.SubscribeRequest, payload);
        return DrainChunks(first);
    }

    /// <summary>Invokes a command and returns the raw InvokeResponse message.</summary>
    public MatterMessage Invoke(CommandPath path, Action<TlvWriter> writeFields) =>
        SendSecure(ImOpcode.InvokeRequest,
            InvokeInteraction.EncodeRequest([new InvokedCommand(path, InvokeInteraction.EncodeCommandFields(writeFields))]));

    /// <summary>Writes an attribute and returns the raw WriteResponse message.</summary>
    public MatterMessage Write(AttributePath path, Action<TlvWriter, TlvTag> writeData) =>
        SendSecure(ImOpcode.WriteRequest, WriteInteraction.EncodeRequest([(path, writeData)]));

    /// <summary>
    /// Waits for the device to push a subscription report, acks every chunk, and returns the reassembled
    /// attributes. Throws on timeout — a device that never reports is the failure this is here to catch.
    /// </summary>
    public async Task<IReadOnlyList<ReadInteraction.ReportedAttribute>> ReceiveReportAsync(TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(2));
        while (DateTime.UtcNow < deadline)
        {
            byte[]? datagram;
            lock (_pushGate) _pushed.TryDequeue(out datagram);
            if (datagram is not null)
                return DrainPushedChunks(Decode(datagram));
            await Task.Delay(5).ConfigureAwait(false);
        }
        throw new TimeoutException(
            "The device pushed no subscription report. Either nothing is subscribed to the changed path, or " +
            "the attribute was set with the silent Cluster.Set instead of SetAttribute.");
    }

    /// <summary>True when the device has pushed at least one datagram that hasn't been consumed.</summary>
    public bool HasPendingReport { get { lock (_pushGate) return _pushed.Count > 0; } }

    /// <summary>
    /// The byte size of every datagram the device has sent this controller — pushed reports and replies
    /// alike. Assert these stay within <see cref="UdpMtu"/>: an oversized datagram is dropped in transit, and
    /// from the device's side that looks identical to working correctly, because it encoded and "sent" fine.
    /// </summary>
    public IReadOnlyList<int> DeviceDatagramSizes { get { lock (_pushGate) return _datagramSizes.ToList(); } }

    /// <summary>Throws if the device has ever sent a datagram larger than the MTU.</summary>
    public void AssertAllDatagramsWithinMtu()
    {
        var oversized = DeviceDatagramSizes.Where(size => size > UdpMtu).ToList();
        if (oversized.Count > 0)
            throw new InvalidOperationException(
                $"The device sent {oversized.Count} datagram(s) over the {UdpMtu} B MTU (largest {oversized.Max()} B). " +
                "Large payloads must be split into flow-controlled chunks or a real controller will never receive them.");
    }

    /// <summary>Decrypts a datagram the device sent us.</summary>
    public MatterMessage Decode(byte[] datagram) => MatterMessage.DecodeSecure(datagram, _decryptKey);

    // ---- internals -------------------------------------------------------

    private void CaptureOutboundDatagrams() =>
        _device.SendDatagram = (_, datagram, _) =>
        {
            lock (_pushGate)
            {
                _pushed.Enqueue(datagram);
                _datagramSizes.Add(datagram.Length);
            }
            return Task.CompletedTask;
        };

    /// <summary>Records the wire size of datagrams the device returned synchronously.</summary>
    private IReadOnlyList<byte[]> Track(IReadOnlyList<byte[]> datagrams)
    {
        lock (_pushGate)
            foreach (var datagram in datagrams) _datagramSizes.Add(datagram.Length);
        return datagrams;
    }

    /// <summary>Acks a reply-chunked report (peer-initiated exchange) until the device stops sending.</summary>
    private List<ReadInteraction.ReportedAttribute> DrainChunks(MatterMessage first)
    {
        var all = new List<ReadInteraction.ReportedAttribute>(ReadInteraction.DecodeReport(first.Payload));
        while (true)
        {
            // We initiated this exchange, so our StatusResponse carries the initiator flag.
            var more = SendSecureRaw(ImOpcode.StatusResponse, StatusResponseInteraction.Encode(), first.ExchangeId, isInitiator: true);
            if (more.Count == 0) break;
            var next = Decode(more[0]);
            if (next.Opcode != (byte)ImOpcode.ReportData) break; // e.g. the SubscribeResponse tail
            all.AddRange(ReadInteraction.DecodeReport(next.Payload));
        }
        return all;
    }

    /// <summary>Acks a device-initiated (pushed) chunked report until the device stops sending.</summary>
    private List<ReadInteraction.ReportedAttribute> DrainPushedChunks(MatterMessage first)
    {
        var all = new List<ReadInteraction.ReportedAttribute>(ReadInteraction.DecodeReport(first.Payload));
        while (true)
        {
            // The DEVICE initiated this exchange, so our ack must NOT set the initiator flag.
            var more = SendSecureRaw(ImOpcode.StatusResponse, StatusResponseInteraction.Encode(), first.ExchangeId, isInitiator: false);
            if (more.Count == 0) break;
            var next = Decode(more[0]);
            if (next.Opcode != (byte)ImOpcode.ReportData) break;
            all.AddRange(ReadInteraction.DecodeReport(next.Payload));
        }
        return all;
    }

    private void OpenSecure(ushort deviceSessionId, byte[] encryptKey, byte[] decryptKey, ulong nonceNodeId = 0)
    {
        _sessionId = deviceSessionId;
        _encryptKey = encryptKey;
        _decryptKey = decryptKey;
        _nonceNodeId = nonceNodeId;
    }

    private MatterMessage SendUnsecured(SecureChannelOpcode opcode, byte[] payload)
    {
        var msg = new MatterMessage
        {
            SessionId = 0, MessageCounter = _counter++, SourceNodeId = 0,
            IsInitiator = true, RequiresAck = true,
            Opcode = (byte)opcode, ExchangeId = _exchangeId++, ProtocolId = MatterProtocolId.SecureChannel,
            Payload = payload,
        };
        var responses = Track(_device.ProcessDatagram(msg.Encode(), _peer));
        if (responses.Count == 0) throw new InvalidOperationException($"Device did not answer {opcode}.");
        return MatterMessage.Decode(responses[0]);
    }

    private MatterMessage SendSecure(ImOpcode opcode, byte[] payload)
    {
        var responses = SendSecureRaw(opcode, payload, _exchangeId++, isInitiator: true);
        if (responses.Count == 0) throw new InvalidOperationException($"Device did not answer {opcode}.");
        return Decode(responses[0]);
    }

    private IReadOnlyList<byte[]> SendSecureRaw(ImOpcode opcode, byte[] payload, ushort exchangeId, bool isInitiator)
    {
        var msg = new MatterMessage
        {
            SessionId = _sessionId, MessageCounter = _counter++,
            IsInitiator = isInitiator, RequiresAck = true,
            Opcode = (byte)opcode, ExchangeId = exchangeId, ProtocolId = MatterProtocolId.InteractionModel,
            Payload = payload,
        };
        // Source Node ID is omitted from the header and carried only in the AEAD nonce — the spec-compliant
        // behaviour Apple Home uses, so exercising it here keeps devices honest.
        return Track(_device.ProcessDatagram(msg.EncodeSecure(_encryptKey, _nonceNodeId == 0 ? null : _nonceNodeId), _peer));
    }

    private MatterMessage InvokeOpCreds(uint commandId, Action<TlvWriter> writeFields) =>
        Invoke(new CommandPath(0, 0x003E, commandId), writeFields);

    private static byte[] ReadResponseField(MatterMessage invokeResponse, int fieldTag)
    {
        byte[] result = [];
        var r = new TlvReader(invokeResponse.Payload);
        r.Read();
        r.EnterContainer((ref TlvReader f) =>
        {
            if (f.TagNumber != 1 || !f.IsContainer) return;
            f.EnterContainer((ref TlvReader ib) =>
                ib.EnterContainer((ref TlvReader cmdData) =>
                {
                    if (cmdData.TagNumber != 0 || !cmdData.IsContainer) return;
                    cmdData.EnterContainer((ref TlvReader g) =>
                    {
                        if (g.TagNumber == 1 && g.IsContainer)
                            g.EnterContainer((ref TlvReader field) =>
                            {
                                if (field.TagNumber == fieldTag) result = field.GetBytes().ToArray();
                            });
                    });
                }));
        });
        return result;
    }
}

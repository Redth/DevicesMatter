using System.Security.Cryptography;
using MatterDevice.Commissioning;
using MatterDevice.Commissioning.Case;
using MatterDevice.Commissioning.OperationalCredentials;
using MatterDevice.Commissioning.Pase;
using MatterDevice.Core.Credentials;
using MatterDevice.Core.Crypto;
using MatterDevice.Core.Messaging;
using MatterDevice.Core.Tlv;
using MatterDevice.DataModel;
using MatterDevice.DataModel.Clusters;
using MatterDevice.DataModel.InteractionModel;

namespace MatterDevice.Tests;

/// <summary>
/// The capstone: a commissioner drives the <see cref="MatterDeviceNode"/> orchestrator through the WHOLE
/// commissioning sequence as real (framed, and where applicable encrypted) Matter messages —
/// PASE → encrypted IM (AttestationRequest, CSRRequest, AddTrustedRootCertificate, AddNOC) →
/// CASE → encrypted IM (read the thermostat). It proves the full device works end to end through one
/// integrated entry point, exactly as a controller would drive it over UDP.
/// </summary>
public class CapstoneCommissioningTests
{
    private const uint Passcode = 20202021;
    private const ulong FabricId = 0xFAB000000000001D;
    private const ulong DeviceNodeId = 0x00000000DEDEDEDE;
    private const ulong CommissionerNodeId = 0x000000001234ABCD;
    private const ulong RcacId = 0xCACACACA00000001;
    private const uint ThermostatClusterId = 0x0201;

    [Fact]
    public void Full_commissioning_through_the_orchestrator()
    {
        // ---- the device ----
        var node = new Node();
        node.AddEndpoint(0, DeviceType.RootNode);
        var thermostat = new ThermostatCluster { LocalTemperatureCentiC = 2880 };
        node.AddEndpoint(1, DeviceType.Thermostat).AddCluster(thermostat);

        var dacKey = P256KeyPair.Generate();
        var device = new MatterDeviceNode(new MatterDeviceOptions
        {
            Passcode = Passcode,
            PaseSalt = RandomNumberGenerator.GetBytes(16),
            Attestation = new DeviceAttestationProvider(dacKey,
                RandomNumberGenerator.GetBytes(64), RandomNumberGenerator.GetBytes(64), RandomNumberGenerator.GetBytes(128)),
            DataModel = node,
        });

        // ---- 1. PASE over the wire ----
        var prover = new TestProver(Passcode);
        var pase = new Commissioner(device);

        var reqBytes = prover.BuildPbkdfParamRequest();
        var pbkdfResp = pase.SendUnsecured(SecureChannelOpcode.PbkdfParamRequest, reqBytes, MatterProtocolId.SecureChannel);
        var pbkdfRespMsg = PaseMessages.PbkdfParamResponse.Decode(pbkdfResp.Payload);
        prover.OnPbkdfParamResponse(reqBytes, pbkdfResp.Payload);
        var deviceePaseSessionId = pbkdfRespMsg.ResponderSessionId;

        var pake2 = pase.SendUnsecured(SecureChannelOpcode.PasePake1, prover.BuildPake1(), MatterProtocolId.SecureChannel);
        var statusReport = pase.SendUnsecured(SecureChannelOpcode.PasePake3, prover.OnPake2BuildPake3(pake2.Payload), MatterProtocolId.SecureChannel);
        Assert.Equal((byte)SecureChannelOpcode.StatusReport, statusReport.Opcode);
        Assert.Equal(SecureChannelStatusCode.SessionEstablishmentSuccess, (SecureChannelStatusCode)StatusReport.Decode(statusReport.Payload).ProtocolCode);

        // commissioner's view of the PASE session (encrypt with I2R, decrypt with R2I)
        var (i2r, r2i, _) = prover.SessionKeys!.Value;
        pase.OpenSecure(deviceePaseSessionId, encryptKey: i2r, decryptKey: r2i);

        // ---- 2. attestation + CSR over the encrypted PASE session ----
        InvokeOpCreds(pase, 0x00, w => w.WriteBytes(TlvTag.ContextSpecific(0), RandomNumberGenerator.GetBytes(32))); // AttestationRequest
        var csrResponse = InvokeOpCreds(pase, 0x04, w => w.WriteBytes(TlvTag.ContextSpecific(0), RandomNumberGenerator.GetBytes(32))); // CSRRequest
        var nocsr = OpCredsMessages.DecodeNocsrElements(ReadResponseField(csrResponse, fieldTag: 0));
        var operationalPublicKey = P256KeyPair.PublicKeyFromCsr(nocsr.Csr);

        // ---- 3. commissioner builds fabric, installs root + NOC ----
        var rootKey = P256KeyPair.Generate();
        var root = OperationalCredentials.CreateRootCertificate(rootKey, RcacId);
        var deviceNoc = OperationalCredentials.CreateNodeCertificate(rootKey, root, operationalPublicKey, FabricId, DeviceNodeId);
        var ipk = RandomNumberGenerator.GetBytes(16);

        InvokeOpCreds(pase, 0x0B, w => w.WriteBytes(TlvTag.ContextSpecific(0), root.Encode())); // AddTrustedRootCertificate
        var nocResponse = InvokeOpCreds(pase, 0x06, w =>                                          // AddNOC
        {
            w.WriteBytes(TlvTag.ContextSpecific(0), deviceNoc.Encode());
            w.WriteBytes(TlvTag.ContextSpecific(2), ipk);
        });
        Assert.Equal((byte)NodeOperationalCertStatus.Ok, ReadResponseUInt(nocResponse, fieldTag: 0));
        Assert.Equal(1, device.Fabrics.Count);

        // ---- 4. CASE over the wire ----
        var commissionerKey = P256KeyPair.Generate();
        var commissionerNoc = OperationalCredentials.CreateNodeCertificate(rootKey, root, commissionerKey, FabricId, CommissionerNodeId);
        var caseInitiator = new CaseInitiator(root, ipk, FabricId, DeviceNodeId, commissionerNoc, commissionerKey, 0xB2B2);

        var sigma2 = pase.SendUnsecured(SecureChannelOpcode.CaseSigma1, caseInitiator.BuildSigma1(), MatterProtocolId.SecureChannel);
        var sigma2Decoded = CaseMessages.Sigma2.Decode(sigma2.Payload);
        var caseStatus = pase.SendUnsecured(SecureChannelOpcode.CaseSigma3, caseInitiator.OnSigma2BuildSigma3(sigma2.Payload), MatterProtocolId.SecureChannel);
        Assert.Equal(SecureChannelStatusCode.SessionEstablishmentSuccess, (SecureChannelStatusCode)StatusReport.Decode(caseStatus.Payload).ProtocolCode);

        // ---- 5. read the thermostat over the encrypted CASE session ----
        var (caseI2r, caseR2i, _) = caseInitiator.SessionKeys!.Value;
        var operationalSession = new Commissioner(device);
        operationalSession.OpenSecure(sigma2Decoded.ResponderSessionId, encryptKey: caseI2r, decryptKey: caseR2i, nonceNodeId: CommissionerNodeId);

        var readRequest = ReadInteraction.EncodeRequest(
            [new AttributePath(1, ThermostatClusterId, ThermostatCluster.LocalTemperatureId)]);
        var reportMsg = operationalSession.SendSecure(ImOpcode.ReadRequest, readRequest, MatterProtocolId.InteractionModel);
        var reported = ReadInteraction.DecodeReport(reportMsg.Payload);
        Assert.Equal(2880L, Assert.IsType<long>(reported[0].Value));
    }

    [Fact]
    public void Unknown_session_gets_one_SessionNotFound_then_silence()
    {
        // A peer still using a session from before we restarted: we can't decrypt it, but instead of
        // silently dropping (leaving the peer to wait out its retransmit timeout) we answer once with a
        // SessionNotFound StatusReport so it re-establishes via CASE now. Deduped so retransmits stay quiet.
        var node = new Node();
        node.AddEndpoint(0, DeviceType.RootNode);
        node.AddEndpoint(1, DeviceType.Thermostat).AddCluster(new ThermostatCluster());
        var device = new MatterDeviceNode(new MatterDeviceOptions
        {
            Passcode = Passcode,
            PaseSalt = RandomNumberGenerator.GetBytes(16),
            Attestation = new DeviceAttestationProvider(P256KeyPair.Generate(),
                RandomNumberGenerator.GetBytes(64), RandomNumberGenerator.GetBytes(64), RandomNumberGenerator.GetBytes(128)),
            DataModel = node,
        });

        static byte[] StaleDatagram(ushort sessionId) => new MatterMessage
        {
            SessionId = sessionId,
            IsInitiator = true,
            Opcode = (byte)ImOpcode.ReadRequest,
            ProtocolId = MatterProtocolId.InteractionModel,
            ExchangeId = 1,
            MessageCounter = 7,
            Payload = [1, 2, 3],
        }.EncodeSecure(new byte[16]);

        var reply = MatterMessage.Decode(Assert.Single(device.ProcessDatagram(StaleDatagram(0x2710))));
        Assert.Equal(MatterProtocolId.SecureChannel, reply.ProtocolId);
        Assert.Equal((byte)SecureChannelOpcode.StatusReport, reply.Opcode);
        var status = StatusReport.Decode(reply.Payload);
        Assert.Equal(GeneralStatusCode.Failure, status.GeneralStatus);
        Assert.Equal((ushort)SecureChannelStatusCode.SessionNotFound, status.ProtocolCode);

        // Same stale session id again → no reply (so retransmits can't be used for reflection).
        Assert.Empty(device.ProcessDatagram(StaleDatagram(0x2710)));
    }

    [Fact]
    public async Task Proactive_subscription_reports_are_chunked_within_the_MTU()
    {
        // A wildcard controller subscription (Apple Home reads the whole node) snapshots far more attributes
        // than fit in one UDP datagram. Regression guard for the bug where proactive ReportData was crammed
        // into ONE oversized datagram: the peer silently dropped it, never acked, so the session went idle
        // and was reaped every ~5 min and attribute changes never arrived. Reports must be split into
        // MTU-sized, StatusResponse-driven chunks.
        var node = new Node();
        node.AddEndpoint(0, DeviceType.RootNode);
        var thermostats = new List<ThermostatCluster>();
        for (ushort ep = 1; ep <= 16; ep++) // enough endpoints that a whole-node snapshot spans several chunks
        {
            var t = new ThermostatCluster { LocalTemperatureCentiC = (short)(2000 + ep) };
            node.AddEndpoint(ep, DeviceType.Thermostat).AddCluster(t);
            thermostats.Add(t);
        }

        var (device, op) = EstablishOperationalSession(node);

        var outbound = new List<byte[]>();
        device.SendDatagram = (_, dgram, _) => { outbound.Add(dgram); return Task.CompletedTask; };

        // Subscribe to the whole node (endpoint/cluster/attribute all wildcard); the priming report's first
        // chunk comes back synchronously — we only need the subscription to exist for the proactive path.
        var subscribe = EncodeSubscribeRequest(minIntervalFloor: 0, maxIntervalCeiling: 60, new AttributePath(null, null, null));
        op.SendSecure(ImOpcode.SubscribeRequest, subscribe, MatterProtocolId.InteractionModel);

        // Change a subscribed attribute → the device pushes a proactive report to the peer (via SendDatagram).
        thermostats[0].SetAttribute(ThermostatCluster.LocalTemperatureId, (short)2999);
        for (var i = 0; i < 200 && outbound.Count == 0; i++) await Task.Delay(5);

        Assert.NotEmpty(outbound);
        const int UdpMtu = 1280; // IPv6 minimum MTU; a Matter message is one datagram, so no report may exceed it.
        var firstReport = op.Decode(outbound[0]);
        Assert.Equal((byte)ImOpcode.ReportData, firstReport.Opcode);
        Assert.True(outbound[0].Length <= UdpMtu,
            $"proactive report was {outbound[0].Length} B — it must be chunked under the {UdpMtu} B MTU, not sent whole");

        // Ack the first chunk. The device initiated this exchange, so the peer's ack is NOT the initiator —
        // the node keys pending chunks on that flag, so this both drives the next chunk and proves the
        // device-initiated exchange can't be confused with a reply to a peer-initiated read/subscribe.
        var followOn = op.SendSecureExchange(ImOpcode.StatusResponse, EncodeEmptyStatusResponse(), firstReport.ExchangeId, isInitiator: false);
        var nextDatagram = Assert.Single(followOn);
        Assert.Equal((byte)ImOpcode.ReportData, op.Decode(nextDatagram).Opcode); // a further chunk was released
        Assert.True(nextDatagram.Length <= UdpMtu, $"continuation chunk was {nextDatagram.Length} B — over the {UdpMtu} B MTU");
    }

    /// <summary>Drives PASE → operational CASE end to end and returns the device plus an open operational
    /// session, so a test can exercise post-commissioning interactions without repeating the whole handshake.
    /// Mirrors the first half of <see cref="Full_commissioning_through_the_orchestrator"/>.</summary>
    private static (MatterDeviceNode device, Commissioner op) EstablishOperationalSession(Node node)
    {
        var device = new MatterDeviceNode(new MatterDeviceOptions
        {
            Passcode = Passcode,
            PaseSalt = RandomNumberGenerator.GetBytes(16),
            Attestation = new DeviceAttestationProvider(P256KeyPair.Generate(),
                RandomNumberGenerator.GetBytes(64), RandomNumberGenerator.GetBytes(64), RandomNumberGenerator.GetBytes(128)),
            DataModel = node,
        });

        var prover = new TestProver(Passcode);
        var pase = new Commissioner(device);
        var reqBytes = prover.BuildPbkdfParamRequest();
        var pbkdfResp = pase.SendUnsecured(SecureChannelOpcode.PbkdfParamRequest, reqBytes, MatterProtocolId.SecureChannel);
        prover.OnPbkdfParamResponse(reqBytes, pbkdfResp.Payload);
        var devicePaseSessionId = PaseMessages.PbkdfParamResponse.Decode(pbkdfResp.Payload).ResponderSessionId;

        var pake2 = pase.SendUnsecured(SecureChannelOpcode.PasePake1, prover.BuildPake1(), MatterProtocolId.SecureChannel);
        pase.SendUnsecured(SecureChannelOpcode.PasePake3, prover.OnPake2BuildPake3(pake2.Payload), MatterProtocolId.SecureChannel);
        var (i2r, r2i, _) = prover.SessionKeys!.Value;
        pase.OpenSecure(devicePaseSessionId, encryptKey: i2r, decryptKey: r2i);

        InvokeOpCreds(pase, 0x00, w => w.WriteBytes(TlvTag.ContextSpecific(0), RandomNumberGenerator.GetBytes(32)));  // AttestationRequest
        var csrResponse = InvokeOpCreds(pase, 0x04, w => w.WriteBytes(TlvTag.ContextSpecific(0), RandomNumberGenerator.GetBytes(32))); // CSRRequest
        var nocsr = OpCredsMessages.DecodeNocsrElements(ReadResponseField(csrResponse, fieldTag: 0));
        var operationalPublicKey = P256KeyPair.PublicKeyFromCsr(nocsr.Csr);

        var rootKey = P256KeyPair.Generate();
        var root = OperationalCredentials.CreateRootCertificate(rootKey, RcacId);
        var deviceNoc = OperationalCredentials.CreateNodeCertificate(rootKey, root, operationalPublicKey, FabricId, DeviceNodeId);
        var ipk = RandomNumberGenerator.GetBytes(16);
        InvokeOpCreds(pase, 0x0B, w => w.WriteBytes(TlvTag.ContextSpecific(0), root.Encode())); // AddTrustedRootCertificate
        InvokeOpCreds(pase, 0x06, w =>                                                          // AddNOC
        {
            w.WriteBytes(TlvTag.ContextSpecific(0), deviceNoc.Encode());
            w.WriteBytes(TlvTag.ContextSpecific(2), ipk);
        });

        var commissionerKey = P256KeyPair.Generate();
        var commissionerNoc = OperationalCredentials.CreateNodeCertificate(rootKey, root, commissionerKey, FabricId, CommissionerNodeId);
        var caseInitiator = new CaseInitiator(root, ipk, FabricId, DeviceNodeId, commissionerNoc, commissionerKey, 0xB2B2);
        var sigma2 = pase.SendUnsecured(SecureChannelOpcode.CaseSigma1, caseInitiator.BuildSigma1(), MatterProtocolId.SecureChannel);
        var sigma2Decoded = CaseMessages.Sigma2.Decode(sigma2.Payload);
        pase.SendUnsecured(SecureChannelOpcode.CaseSigma3, caseInitiator.OnSigma2BuildSigma3(sigma2.Payload), MatterProtocolId.SecureChannel);

        var (caseI2r, caseR2i, _) = caseInitiator.SessionKeys!.Value;
        var op = new Commissioner(device);
        op.OpenSecure(sigma2Decoded.ResponderSessionId, encryptKey: caseI2r, decryptKey: caseR2i, nonceNodeId: CommissionerNodeId);
        return (device, op);
    }

    private static byte[] EncodeSubscribeRequest(ushort minIntervalFloor, ushort maxIntervalCeiling, params AttributePath[] paths)
    {
        var w = new TlvWriter();
        w.StartStructure(TlvTag.Anonymous)
            .WriteBool(TlvTag.ContextSpecific(0), false)              // KeepSubscriptions
            .WriteUInt(TlvTag.ContextSpecific(1), minIntervalFloor)
            .WriteUInt(TlvTag.ContextSpecific(2), maxIntervalCeiling);
        w.StartArray(TlvTag.ContextSpecific(3));                       // AttributeRequests
        foreach (var p in paths) p.Write(w, TlvTag.Anonymous);
        w.EndContainer();
        w.WriteUInt(TlvTag.ContextSpecific(ImConstants.InteractionModelRevisionTag), ImConstants.InteractionModelRevision);
        w.EndContainer();
        return w.ToArray();
    }

    private static byte[] EncodeEmptyStatusResponse() =>
        new TlvWriter().StartStructure(TlvTag.Anonymous).WriteUInt(TlvTag.ContextSpecific(0), 0).EndContainer().ToArray();

    private static MatterMessage InvokeOpCreds(Commissioner c, uint commandId, Action<TlvWriter> writeFields)
    {
        var command = new InvokedCommand(new CommandPath(0, 0x003E, commandId),
            InvokeInteraction.EncodeCommandFields(writeFields));
        var invoke = InvokeInteraction.EncodeRequest([command]);
        return c.SendSecure(ImOpcode.InvokeRequest, invoke, MatterProtocolId.InteractionModel);
    }

    // ---- helpers to pull fields out of an InvokeResponse's response command ----
    private static byte[] ReadResponseField(MatterMessage invokeResponse, int fieldTag)
    {
        byte[] result = [];
        WalkResponseFields(invokeResponse.Payload, (ref TlvReader f) => { if (f.TagNumber == fieldTag) result = f.GetBytes().ToArray(); });
        return result;
    }

    private static ulong ReadResponseUInt(MatterMessage invokeResponse, int fieldTag)
    {
        ulong result = 0;
        WalkResponseFields(invokeResponse.Payload, (ref TlvReader f) => { if (f.TagNumber == fieldTag) result = f.GetUInt(); });
        return result;
    }

    private static void WalkResponseFields(byte[] invokeResponseTlv, TlvReader.ReadFieldDelegate onField)
    {
        var r = new TlvReader(invokeResponseTlv);
        r.Read(); // InvokeResponseMessage struct
        r.EnterContainer((ref TlvReader f) =>
        {
            if (f.TagNumber != 1 || !f.IsContainer) return;            // InvokeResponses array
            f.EnterContainer((ref TlvReader ib) =>
            {
                ib.EnterContainer((ref TlvReader cmdData) =>           // InvokeResponseIB
                {
                    if (cmdData.TagNumber != 0 || !cmdData.IsContainer) return; // CommandDataIB (command [0])
                    cmdData.EnterContainer((ref TlvReader g) =>
                    {
                        if (g.TagNumber == 1 && g.IsContainer)          // CommandFields
                            g.EnterContainer(onField);
                    });
                });
            });
        });
    }

    /// <summary>A commissioner-side message pump for one device, handling plaintext + encrypted framing.</summary>
    private sealed class Commissioner(MatterDeviceNode device)
    {
        private readonly MatterDeviceNode _device = device;
        private readonly object _peer = new(); // opaque transport handle; the node stamps it on the session so it can push reports
        private ushort _exchangeId = 0x5000;
        private uint _counter = 1;
        private ushort _sessionId;
        private byte[]? _encryptKey, _decryptKey;
        private ulong _nonceNodeId; // initiator's operational node id for the AEAD nonce (0 over PASE)

        public void OpenSecure(ushort deviceSessionId, byte[] encryptKey, byte[] decryptKey, ulong nonceNodeId = 0)
        {
            _sessionId = deviceSessionId;
            _encryptKey = encryptKey;
            _decryptKey = decryptKey;
            _nonceNodeId = nonceNodeId;
        }

        public MatterMessage SendUnsecured(SecureChannelOpcode opcode, byte[] payload, MatterProtocolId protocol)
        {
            var msg = new MatterMessage
            {
                SessionId = 0, MessageCounter = _counter++, SourceNodeId = 0,
                IsInitiator = true, RequiresAck = true,
                Opcode = (byte)opcode, ExchangeId = _exchangeId++, ProtocolId = protocol, Payload = payload,
            };
            var responses = _device.ProcessDatagram(msg.Encode(), _peer);
            return MatterMessage.Decode(Assert.Single(responses));
        }

        public MatterMessage SendSecure(ImOpcode opcode, byte[] payload, MatterProtocolId protocol)
        {
            var msg = new MatterMessage
            {
                SessionId = _sessionId, MessageCounter = _counter++,
                IsInitiator = true, RequiresAck = true,
                Opcode = (byte)opcode, ExchangeId = _exchangeId++, ProtocolId = protocol, Payload = payload,
            };
            // Omit the Source Node ID from the header and put the operational node id only in the nonce —
            // the spec-compliant (Apple Home) behaviour the device must handle.
            var responses = _device.ProcessDatagram(msg.EncodeSecure(_encryptKey!, _nonceNodeId == 0 ? null : _nonceNodeId), _peer);
            return MatterMessage.DecodeSecure(Assert.Single(responses), _decryptKey!);
        }

        /// <summary>Sends on a caller-chosen exchange with an explicit initiator flag — used to ack a report the
        /// device initiated (there the peer is NOT the exchange initiator), and returns whatever the node emits.</summary>
        public IReadOnlyList<byte[]> SendSecureExchange(ImOpcode opcode, byte[] payload, ushort exchangeId, bool isInitiator)
        {
            var msg = new MatterMessage
            {
                SessionId = _sessionId, MessageCounter = _counter++,
                IsInitiator = isInitiator, RequiresAck = true,
                Opcode = (byte)opcode, ExchangeId = exchangeId, ProtocolId = MatterProtocolId.InteractionModel, Payload = payload,
            };
            return _device.ProcessDatagram(msg.EncodeSecure(_encryptKey!, _nonceNodeId == 0 ? null : _nonceNodeId), _peer);
        }

        /// <summary>Decrypts a datagram the device pushed to us (e.g. a proactive subscription report).</summary>
        public MatterMessage Decode(byte[] datagram) => MatterMessage.DecodeSecure(datagram, _decryptKey!);
    }
}

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
            var responses = _device.ProcessDatagram(msg.Encode());
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
            var responses = _device.ProcessDatagram(msg.EncodeSecure(_encryptKey!, _nonceNodeId == 0 ? null : _nonceNodeId));
            return MatterMessage.DecodeSecure(Assert.Single(responses), _decryptKey!);
        }
    }
}

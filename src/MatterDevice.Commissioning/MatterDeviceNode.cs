using MatterDevice.Commissioning.Case;
using MatterDevice.Commissioning.OperationalCredentials;
using MatterDevice.Commissioning.Pase;
using MatterDevice.Core.Credentials;
using MatterDevice.Core.Messaging;
using MatterDevice.Core.Session;
using MatterDevice.Core.Tlv;
using MatterDevice.DataModel;
using MatterDevice.DataModel.Clusters;
using MatterDevice.DataModel.InteractionModel;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MatterDevice.Commissioning;

/// <summary>Configuration for a <see cref="MatterDeviceNode"/>.</summary>
public sealed class MatterDeviceOptions
{
    public required uint Passcode { get; init; }
    public required byte[] PaseSalt { get; init; }
    public int PaseIterations { get; init; } = 1000;
    public required DeviceAttestationProvider Attestation { get; init; }
    public required Node DataModel { get; init; }
    public CommandHandler? ApplicationCommandHandler { get; init; }
}

/// <summary>
/// A complete commissionable Matter node: the transport-agnostic orchestrator that sequences every layer —
/// PASE, the encrypted Operational-Credentials commissioning (attestation → CSR → AddNOC), CASE, and the
/// encrypted Interaction Model — driven by raw datagrams. Feed it <see cref="ProcessDatagram"/>; it returns
/// the response datagrams. A UDP/host wrapper just pumps packets in and out.
/// </summary>
public sealed class MatterDeviceNode
{
    private readonly MatterDeviceOptions _options;
    private readonly ILogger _log;
    private readonly SessionManager _sessions = new();
    private readonly FabricTable _fabrics = new();
    private readonly InteractionDispatcher _dispatcher;

    private PaseResponder? _pase;
    private DeviceCommissioning? _commissioning;
    private CaseResponder? _case;

    public MatterDeviceNode(MatterDeviceOptions options, ILogger? logger = null)
    {
        _options = options;
        _log = logger ?? NullLogger.Instance;
        _dispatcher = new InteractionDispatcher(options.DataModel);
    }

    public FabricTable Fabrics => _fabrics;
    public IReadOnlyCollection<SecureSession> Sessions => _sessions.Active;

    /// <summary>Raised when a fabric is committed via AddNOC — the host can begin operational advertising.</summary>
    public event Action<Fabric>? FabricCommissioned;

    /// <summary>Processes one inbound datagram and returns the response datagram(s) (usually one).</summary>
    public IReadOnlyList<byte[]> ProcessDatagram(byte[] datagram)
    {
        var (header, _) = MatterMessage.DecodeMessageHeader(datagram);
        return header.SessionId == 0
            ? ProcessUnsecured(datagram)
            : ProcessSecure(header.SessionId, datagram);
    }

    // ---- unsecured session: PASE + CASE handshakes ----------------------

    private IReadOnlyList<byte[]> ProcessUnsecured(byte[] datagram)
    {
        var msg = MatterMessage.Decode(datagram);
        if (msg.ProtocolId != MatterProtocolId.SecureChannel)
            return [];

        switch ((SecureChannelOpcode)msg.Opcode)
        {
            case SecureChannelOpcode.PbkdfParamRequest:
            {
                var localId = _sessions.AllocateLocalSessionId();
                _pase = new PaseResponder(_options.Passcode, _options.PaseSalt, _options.PaseIterations, localId);
                _commissioning = new DeviceCommissioning(_options.Attestation, _fabrics);
                _log.LogInformation("← PBKDFParamRequest (local session {Id})", localId);
                var resp = _pase.OnPbkdfParamRequest(msg.Payload);
                return [Reply(msg, SecureChannelOpcode.PbkdfParamResponse, resp.Encode(), requiresAck: true)];
            }
            case SecureChannelOpcode.PasePake1:
            {
                var pake2 = _pase!.OnPake1(msg.Payload);
                return [Reply(msg, SecureChannelOpcode.PasePake2, pake2.Encode(), requiresAck: true)];
            }
            case SecureChannelOpcode.PasePake3:
            {
                var paseSession = _pase!.OnPake3(msg.Payload);
                if (paseSession is null)
                    return [Reply(msg, SecureChannelOpcode.StatusReport, StatusReport.Failure(SecureChannelStatusCode.InvalidParameter).Encode(), false)];
                _sessions.Add(new SecureSession
                {
                    LocalSessionId = paseSession.LocalSessionId,
                    PeerSessionId = paseSession.PeerSessionId,
                    Origin = SessionOrigin.Pase,
                    DecryptKey = paseSession.I2RKey, // device decrypts inbound with I2R
                    EncryptKey = paseSession.R2IKey, // device encrypts outbound with R2I
                    AttestationChallenge = paseSession.AttestationChallenge,
                });
                _log.LogInformation("✓ PASE session {Id} established", paseSession.LocalSessionId);
                return [Reply(msg, SecureChannelOpcode.StatusReport, StatusReport.SessionEstablished().Encode(), false)];
            }
            case SecureChannelOpcode.CaseSigma1:
            {
                _case = new CaseResponder(_fabrics, _sessions.AllocateLocalSessionId());
                _log.LogInformation("← CASE Sigma1");
                var sigma2 = _case.OnSigma1(msg.Payload);
                return [Reply(msg, SecureChannelOpcode.CaseSigma2, sigma2.Encode(), requiresAck: true)];
            }
            case SecureChannelOpcode.CaseSigma3:
            {
                var opSession = _case!.OnSigma3(msg.Payload);
                if (opSession is null)
                    return [Reply(msg, SecureChannelOpcode.StatusReport, StatusReport.Failure(SecureChannelStatusCode.InvalidParameter).Encode(), false)];
                _sessions.Add(opSession);
                _log.LogInformation("✓ CASE operational session {Id} established", opSession.LocalSessionId);
                return [Reply(msg, SecureChannelOpcode.StatusReport, StatusReport.SessionEstablished().Encode(), false)];
            }
            default:
                return [];
        }
    }

    // ---- secure session: Interaction Model ------------------------------

    private IReadOnlyList<byte[]> ProcessSecure(ushort localSessionId, byte[] datagram)
    {
        var session = _sessions.Find(localSessionId);
        if (session is null) { _log.LogWarning("No session {Id}", localSessionId); return []; }

        MatterMessage msg;
        try { msg = MatterMessage.DecodeSecure(datagram, session.DecryptKey); }
        catch (Core.Crypto.AeadAuthenticationException) { _log.LogWarning("Decrypt failed for session {Id}", localSessionId); return []; }

        if (session.AcceptInbound(msg.MessageCounter) == MessageReceptionState.Result.Duplicate)
            return []; // duplicate already processed
        if (msg.ProtocolId != MatterProtocolId.InteractionModel)
            return [];

        byte[]? responsePayload = (ImOpcode)msg.Opcode switch
        {
            ImOpcode.ReadRequest => HandleRead(msg.Payload),
            ImOpcode.InvokeRequest => HandleInvoke(msg.Payload, session),
            _ => null,
        };
        if (responsePayload is null)
            return [];

        var responseOpcode = (ImOpcode)msg.Opcode == ImOpcode.ReadRequest ? ImOpcode.ReportData : ImOpcode.InvokeResponse;
        var reply = new MatterMessage
        {
            IsInitiator = false,
            IsAck = msg.RequiresAck,
            AckedMessageCounter = msg.RequiresAck ? msg.MessageCounter : null,
            Opcode = (byte)responseOpcode,
            ExchangeId = msg.ExchangeId,
            ProtocolId = MatterProtocolId.InteractionModel,
            Payload = responsePayload,
            SourceNodeId = session.LocalNodeId == 0 ? null : session.LocalNodeId,
        };
        return [session.Encode(reply)];
    }

    private byte[] HandleRead(byte[] payload)
    {
        var reports = _dispatcher.Read(ReadInteraction.DecodeRequest(payload));
        return ReadInteraction.EncodeReport(reports);
    }

    private byte[] HandleInvoke(byte[] payload, SecureSession session)
    {
        var commands = InvokeInteraction.DecodeRequest(payload);
        var results = new List<CommandResult>();
        foreach (var cmd in commands)
            results.Add(DispatchCommand(cmd, session));
        return InvokeInteraction.EncodeResponse(results);
    }

    private CommandResult DispatchCommand(InvokedCommand cmd, SecureSession session) => cmd.Path.Cluster switch
    {
        OperationalCredentialsClusterId => HandleOpCredsCommand(cmd, session),
        GeneralCommissioningCluster.ClusterId => HandleGeneralCommissioningCommand(cmd),
        _ => _options.ApplicationCommandHandler is { } h
            ? _dispatcher.Invoke([cmd], h)[0]
            : new CommandResult(cmd.Path, ImStatus.UnsupportedCommand),
    };

    private const uint OperationalCredentialsClusterId = 0x003E;

    /// <summary>ArmFailSafe / SetRegulatoryConfig / CommissioningComplete → their *Response with errorCode = OK.</summary>
    private static CommandResult HandleGeneralCommissioningCommand(InvokedCommand cmd)
    {
        // each request command id maps to its response id (request + 1); response = { 0: errorCode, 1: debugText }
        uint? responseId = cmd.Path.Command switch
        {
            GeneralCommissioningCluster.ArmFailSafeId => GeneralCommissioningCluster.ArmFailSafeResponseId,
            GeneralCommissioningCluster.SetRegulatoryConfigId => GeneralCommissioningCluster.SetRegulatoryConfigResponseId,
            GeneralCommissioningCluster.CommissioningCompleteId => GeneralCommissioningCluster.CommissioningCompleteResponseId,
            _ => null,
        };
        if (responseId is null)
            return new CommandResult(cmd.Path, ImStatus.UnsupportedCommand);

        return ResponseCommand(cmd.Path, responseId.Value, w =>
        {
            w.WriteUInt(TlvTag.ContextSpecific(0), (byte)CommissioningError.Ok);
            w.WriteString(TlvTag.ContextSpecific(1), "");
        });
    }

    private CommandResult HandleOpCredsCommand(InvokedCommand cmd, SecureSession session)
    {
        var fields = OpCredsCommandFields.Parse(cmd.FieldsTlv);
        var challenge = session.AttestationChallenge;

        switch (cmd.Path.Command)
        {
            case 0x00: // AttestationRequest
            {
                var result = _commissioning!.HandleAttestationRequest(fields.Bytes(0), challenge);
                return ResponseCommand(cmd.Path, 0x01, w =>
                {
                    w.WriteBytes(TlvTag.ContextSpecific(0), result.AttestationElements);
                    w.WriteBytes(TlvTag.ContextSpecific(1), result.Signature);
                });
            }
            case 0x02: // CertificateChainRequest
            {
                var cert = _commissioning!.HandleCertificateChainRequest((int)fields.UInt(0));
                return ResponseCommand(cmd.Path, 0x03, w => w.WriteBytes(TlvTag.ContextSpecific(0), cert));
            }
            case 0x04: // CSRRequest
            {
                var result = _commissioning!.HandleCsrRequest(fields.Bytes(0), challenge);
                return ResponseCommand(cmd.Path, 0x05, w =>
                {
                    w.WriteBytes(TlvTag.ContextSpecific(0), result.NocsrElements);
                    w.WriteBytes(TlvTag.ContextSpecific(1), result.Signature);
                });
            }
            case 0x0B: // AddTrustedRootCertificate
                _commissioning!.HandleAddTrustedRoot(fields.Bytes(0));
                return new CommandResult(cmd.Path, ImStatus.Success);
            case 0x09: // UpdateFabricLabel → NOCResponse(Ok)
                return ResponseCommand(cmd.Path, 0x08, w =>
                {
                    w.WriteUInt(TlvTag.ContextSpecific(0), (byte)NodeOperationalCertStatus.Ok);
                    w.WriteUInt(TlvTag.ContextSpecific(1), (byte)1); // fabric index
                    w.WriteString(TlvTag.ContextSpecific(2), "");
                });
            case 0x06: // AddNOC
            {
                var (status, fabricIndex) = _commissioning!.HandleAddNoc(fields.Bytes(0), fields.Bytes(2));
                if (status == NodeOperationalCertStatus.Ok && fabricIndex is { } idx)
                {
                    OperationalCredentialsClusterOnRoot()?.OnFabricAdded(idx);
                    if (_fabrics.Get(idx) is { } fabric)
                        FabricCommissioned?.Invoke(fabric);
                }
                return ResponseCommand(cmd.Path, 0x08, w =>
                {
                    w.WriteUInt(TlvTag.ContextSpecific(0), (byte)status);
                    if (fabricIndex is { } fi) w.WriteUInt(TlvTag.ContextSpecific(1), fi);
                    w.WriteString(TlvTag.ContextSpecific(2), ""); // debugText
                });
            }
            default:
                return new CommandResult(cmd.Path, ImStatus.UnsupportedCommand);
        }
    }

    private static CommandResult ResponseCommand(CommandPath path, uint responseCommandId, Action<TlvWriter> writeFields) =>
        new(path, ImStatus.Success) { ResponseCommandId = responseCommandId, WriteResponseFields = writeFields };

    private OperationalCredentialsCluster? OperationalCredentialsClusterOnRoot() =>
        _options.DataModel.Endpoints.FirstOrDefault(e => e.Id == 0)?
            .Clusters.OfType<OperationalCredentialsCluster>().FirstOrDefault();

    private byte[] Reply(MatterMessage request, SecureChannelOpcode opcode, byte[] payload, bool requiresAck)
    {
        var reply = new MatterMessage
        {
            SessionId = 0,
            MessageCounter = NextUnsecuredCounter(),
            IsInitiator = false,
            IsAck = request.RequiresAck,
            AckedMessageCounter = request.RequiresAck ? request.MessageCounter : null,
            RequiresAck = requiresAck,
            Opcode = (byte)opcode,
            ExchangeId = request.ExchangeId,
            ProtocolId = MatterProtocolId.SecureChannel,
            Payload = payload,
        };
        return reply.Encode();
    }

    private uint _unsecuredCounter = 1;
    private uint NextUnsecuredCounter() => _unsecuredCounter++;
}

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

    /// <summary>Optional fabric persistence — when set, commissioned pairings survive restarts.</summary>
    public Persistence.IFabricStore? FabricStore { get; init; }
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

    private readonly List<Subscription> _subscriptions = [];
    private readonly Lock _subGate = new();
    private uint _nextSubscriptionId = 1;
    private ushort _exchangeCounter = 0xE000;

    /// <summary>Set by the host to push an asynchronous datagram (a subscription report) to a peer token.</summary>
    public Func<object, byte[], CancellationToken, Task>? SendDatagram { get; set; }

    public MatterDeviceNode(MatterDeviceOptions options, ILogger? logger = null)
    {
        _options = options;
        _log = logger ?? NullLogger.Instance;
        _dispatcher = new InteractionDispatcher(options.DataModel);

        // Push reports when any attribute changes (live monitoring).
        foreach (var endpoint in options.DataModel.Endpoints)
            foreach (var cluster in endpoint.Clusters)
                cluster.AttributeChanged += (_, _) => _ = PublishChangedAsync(endpoint.Id, cluster.Id);
    }

    /// <summary>A controller's active subscription: which paths to report and how often, on which session.</summary>
    private sealed class Subscription
    {
        public required uint Id { get; init; }
        public required SecureSession Session { get; init; }
        public required IReadOnlyList<AttributePath> Paths { get; init; }
        public required ushort MaxInterval { get; init; }
        public DateTime LastReportUtc { get; set; }
    }

    public FabricTable Fabrics => _fabrics;
    public IReadOnlyCollection<SecureSession> Sessions => _sessions.Active;

    /// <summary>Raised when a fabric is committed via AddNOC <em>or restored from storage</em> — the host
    /// can begin operational advertising for it.</summary>
    public event Action<Fabric>? FabricCommissioned;

    /// <summary>
    /// Loads any persisted fabrics from <see cref="MatterDeviceOptions.FabricStore"/> into the live table and
    /// raises <see cref="FabricCommissioned"/> for each, so the host advertises them operationally and already
    /// paired controllers reconnect via CASE without re-commissioning. Call once at startup, after wiring
    /// <see cref="FabricCommissioned"/>.
    /// </summary>
    public void RestoreFabrics()
    {
        if (_options.FabricStore is null) return;
        var restored = _options.FabricStore.Load();
        foreach (var fabric in restored)
        {
            _fabrics.Restore(fabric);
            OperationalCredentialsClusterOnRoot()?.OnFabricAdded(fabric.FabricIndex);
            _log.LogInformation("Restored fabric {Index} (node 0x{Node:X16}) from storage", fabric.FabricIndex, fabric.NodeId);
            FabricCommissioned?.Invoke(fabric);
        }
        if (restored.Count > 0)
            _log.LogInformation("Restored {Count} fabric(s) — paired controllers can reconnect without re-pairing.", restored.Count);
    }

    /// <summary>
    /// Processes one inbound datagram and returns the response datagram(s). <paramref name="peer"/> is an
    /// opaque transport token (e.g. the sender's UDP endpoint) used to push asynchronous subscription reports.
    /// </summary>
    public IReadOnlyList<byte[]> ProcessDatagram(byte[] datagram, object? peer = null)
    {
        var (header, _) = MatterMessage.DecodeMessageHeader(datagram);
        return header.SessionId == 0
            ? ProcessUnsecured(datagram)
            : ProcessSecure(header.SessionId, datagram, peer);
    }

    /// <summary>The host calls this periodically (e.g. once a second) to emit subscription heartbeat reports.</summary>
    public async Task TickAsync(CancellationToken ct = default)
    {
        foreach (var sub in SubscriptionsDue())
            await SendSubscriptionReportAsync(sub, ct).ConfigureAwait(false);
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
                _log.LogInformation("← PBKDFParamRequest (local session {Id}, counter {Ctr}, requiresAck {Ack}, srcNodeId {Src}, {Len} bytes)",
                    localId, msg.MessageCounter, msg.RequiresAck, msg.SourceNodeId is { } s ? s.ToString("X16") : "none", msg.Payload.Length);
                var resp = _pase.OnPbkdfParamRequest(msg.Payload);
                _log.LogInformation("→ PBKDFParamResponse");
                return [Reply(msg, SecureChannelOpcode.PbkdfParamResponse, resp.Encode(), requiresAck: true)];
            }
            case SecureChannelOpcode.PasePake1:
            {
                _log.LogInformation("← Pake1  → Pake2");
                var pake2 = _pase!.OnPake1(msg.Payload);
                return [Reply(msg, SecureChannelOpcode.PasePake2, pake2.Encode(), requiresAck: true)];
            }
            case SecureChannelOpcode.PasePake3:
            {
                _log.LogInformation("← Pake3");
                var paseSession = _pase!.OnPake3(msg.Payload);
                if (paseSession is null)
                {
                    _log.LogWarning("Pake3 confirmation failed (passcode/transcript mismatch) — sending failure StatusReport");
                    return [Reply(msg, SecureChannelOpcode.StatusReport, StatusReport.Failure(SecureChannelStatusCode.InvalidParameter).Encode(), false)];
                }
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

    private IReadOnlyList<byte[]> ProcessSecure(ushort localSessionId, byte[] datagram, object? peer)
    {
        var session = _sessions.Find(localSessionId);
        if (session is null) { _log.LogWarning("No session {Id}", localSessionId); return []; }
        if (peer is not null) session.Peer = peer;

        MatterMessage msg;
        try { msg = MatterMessage.DecodeSecure(datagram, session.DecryptKey); }
        catch (Core.Crypto.AeadAuthenticationException) { _log.LogWarning("Decrypt failed for session {Id}", localSessionId); return []; }

        if (session.AcceptInbound(msg.MessageCounter) == MessageReceptionState.Result.Duplicate)
            return []; // duplicate already processed
        _log.LogInformation("← secure msg: protocol {Protocol} opcode 0x{Op:X2} on session {Sid}", msg.ProtocolId, msg.Opcode, localSessionId);
        if (msg.ProtocolId != MatterProtocolId.InteractionModel)
            return [];

        switch ((ImOpcode)msg.Opcode)
        {
            case ImOpcode.SubscribeRequest:
                return HandleSubscribe(msg, session);
            case ImOpcode.ReadRequest:
                // A read's ReportData is chunked when it exceeds the single-message size limit.
                var reports = _dispatcher.Read(ReadInteraction.DecodeRequest(msg.Payload));
                _log.LogInformation("← ReadRequest → {Count} attributes", reports.Count);
                return SendReportChunks(session, msg, reports, subscriptionId: null, isRead: true);
            case ImOpcode.StatusResponse:
                // The peer is acking a report — drive the next chunk if one is pending, else nothing.
                return ContinueChunks(session, msg);
        }

        byte[]? responsePayload = (ImOpcode)msg.Opcode switch
        {
            ImOpcode.InvokeRequest => HandleInvoke(msg.Payload, session),
            ImOpcode.WriteRequest => HandleWrite(msg.Payload),
            _ => null,
        };
        if (responsePayload is null)
            return [];

        var responseOpcode = (ImOpcode)msg.Opcode == ImOpcode.WriteRequest ? ImOpcode.WriteResponse : ImOpcode.InvokeResponse;
        return [session.Encode(ReplyMessage(session, msg, responseOpcode, responsePayload))];
    }

    private MatterMessage ReplyMessage(SecureSession session, MatterMessage request, ImOpcode opcode, byte[] payload) => new()
    {
        IsInitiator = false,
        IsAck = request.RequiresAck,
        AckedMessageCounter = request.RequiresAck ? request.MessageCounter : null,
        Opcode = (byte)opcode,
        ExchangeId = request.ExchangeId,
        ProtocolId = MatterProtocolId.InteractionModel,
        Payload = payload,
        SourceNodeId = session.LocalNodeId == 0 ? null : session.LocalNodeId,
    };

    // ---- read/report chunking (large ReportData split across flow-controlled messages) --------------

    private const int MaxReportPayloadSize = 900;
    // Per (session, exchange): the messages still to send, each driven by the peer's next StatusResponse.
    private readonly Dictionary<(ushort Session, ushort Exchange), Queue<(ImOpcode Opcode, byte[] Payload)>> _pendingChunks = [];

    private IReadOnlyList<byte[]> SendReportChunks(SecureSession session, MatterMessage request, IReadOnlyList<AttributeReport> reports, uint? subscriptionId, bool isRead, byte[]? followUp = null)
    {
        var chunks = ChunkReports(reports, subscriptionId, isRead);
        var first = ReplyMessage(session, request, ImOpcode.ReportData, chunks[0]);
        first.RequiresAck = true;
        var datagrams = new List<byte[]> { session.Encode(first) };

        // Remaining chunks, then (for a subscription) the SubscribeResponse, are sent on the peer's acks.
        var queue = new Queue<(ImOpcode, byte[])>();
        for (var i = 1; i < chunks.Count; i++) queue.Enqueue((ImOpcode.ReportData, chunks[i]));
        if (followUp is not null) queue.Enqueue((ImOpcode.SubscribeResponse, followUp));
        if (queue.Count > 0)
        {
            lock (_subGate) _pendingChunks[(session.LocalSessionId, request.ExchangeId)] = queue;
            if (chunks.Count > 1) _log.LogInformation("  report split into {Chunks} chunks", chunks.Count);
        }
        return datagrams;
    }

    private IReadOnlyList<byte[]> ContinueChunks(SecureSession session, MatterMessage statusMsg)
    {
        var key = (session.LocalSessionId, statusMsg.ExchangeId);
        (ImOpcode Opcode, byte[] Payload)? next = null;
        lock (_subGate)
        {
            if (_pendingChunks.TryGetValue(key, out var queue) && queue.Count > 0)
            {
                next = queue.Dequeue();
                if (queue.Count == 0) _pendingChunks.Remove(key);
            }
        }
        if (next is not { } item)
            return [];

        var msg = new MatterMessage
        {
            IsInitiator = false,
            RequiresAck = true,
            IsAck = statusMsg.RequiresAck,
            AckedMessageCounter = statusMsg.RequiresAck ? statusMsg.MessageCounter : null,
            Opcode = (byte)item.Opcode,
            ExchangeId = statusMsg.ExchangeId,
            ProtocolId = MatterProtocolId.InteractionModel,
            Payload = item.Payload,
            SourceNodeId = session.LocalNodeId == 0 ? null : session.LocalNodeId,
        };
        return [session.Encode(msg)];
    }

    private List<byte[]> ChunkReports(IReadOnlyList<AttributeReport> reports, uint? subscriptionId, bool isRead)
    {
        var groups = new List<List<AttributeReport>>();
        var current = new List<AttributeReport>();
        foreach (var report in reports)
        {
            current.Add(report);
            if (current.Count > 1 && ReadInteraction.EncodeReport(current, false, subscriptionId, true).Length > MaxReportPayloadSize)
            {
                current.RemoveAt(current.Count - 1);
                groups.Add(current);
                current = [report];
            }
        }
        if (current.Count > 0) groups.Add(current);
        if (groups.Count == 0) groups.Add([]); // an empty read still returns one (empty) ReportData

        var payloads = new List<byte[]>();
        for (var i = 0; i < groups.Count; i++)
        {
            var more = i < groups.Count - 1;
            payloads.Add(ReadInteraction.EncodeReport(groups[i], suppressResponse: !more && isRead, subscriptionId, more));
        }
        return payloads;
    }

    private byte[] HandleWrite(byte[] payload)
    {
        var results = _dispatcher.Write(WriteInteraction.DecodeRequest(payload));
        _log.LogInformation("← WriteRequest ({Count} attr) → {Statuses}", results.Count,
            string.Join(",", results.Select(r => $"{r.Path.Cluster:X}/{r.Path.Attribute:X}={r.Status}")));
        return WriteInteraction.EncodeResponse(results);
    }

    // ---- subscriptions --------------------------------------------------

    private IReadOnlyList<byte[]> HandleSubscribe(MatterMessage msg, SecureSession session)
    {
        var req = SubscribeInteraction.DecodeRequest(msg.Payload);
        var maxInterval = req.MaxIntervalCeiling == 0 ? (ushort)60 : req.MaxIntervalCeiling;
        uint subId;
        var sub = new Subscription { Id = 0, Session = session, Paths = req.Paths, MaxInterval = maxInterval, LastReportUtc = DateTime.UtcNow };
        lock (_subGate)
        {
            subId = _nextSubscriptionId++;
            sub = new Subscription { Id = subId, Session = session, Paths = req.Paths, MaxInterval = maxInterval, LastReportUtc = DateTime.UtcNow };
            _subscriptions.Add(sub);
        }
        _log.LogInformation("← SubscribeRequest ({Paths} paths) → subscription {Id}, max {Max}s", req.Paths.Count, subId, maxInterval);

        // Priming ReportData (possibly chunked), then — driven by the peer's StatusResponse — the
        // SubscribeResponse, which MRP-acks that StatusResponse.
        var reports = _dispatcher.Read(req.Paths);
        return SendReportChunks(session, msg, reports, subscriptionId: subId, isRead: false,
            followUp: SubscribeInteraction.EncodeResponse(subId, maxInterval));
    }

    private async Task PublishChangedAsync(ushort endpointId, uint clusterId)
    {
        List<Subscription> affected;
        lock (_subGate)
            affected = _subscriptions.Where(s => s.Paths.Any(p => Covers(p, endpointId, clusterId))).ToList();
        foreach (var sub in affected)
            await SendSubscriptionReportAsync(sub, default).ConfigureAwait(false);
    }

    private List<Subscription> SubscriptionsDue()
    {
        lock (_subGate)
            return _subscriptions.Where(s => (DateTime.UtcNow - s.LastReportUtc).TotalSeconds >= s.MaxInterval).ToList();
    }

    private async Task SendSubscriptionReportAsync(Subscription sub, CancellationToken ct)
    {
        if (SendDatagram is null || sub.Session.Peer is not { } peer)
            return;

        var reports = _dispatcher.Read(sub.Paths);
        var report = new MatterMessage
        {
            IsInitiator = true,
            RequiresAck = true,
            Opcode = (byte)ImOpcode.ReportData,
            ExchangeId = NextExchangeId(),
            ProtocolId = MatterProtocolId.InteractionModel,
            Payload = ReadInteraction.EncodeReport(reports, suppressResponse: false, subscriptionId: sub.Id),
            SourceNodeId = sub.Session.LocalNodeId == 0 ? null : sub.Session.LocalNodeId,
        };
        var datagram = sub.Session.Encode(report);
        sub.LastReportUtc = DateTime.UtcNow;
        try { await SendDatagram(peer, datagram, ct).ConfigureAwait(false); }
        catch (Exception ex) { _log.LogDebug(ex, "Subscription report send failed"); }
    }

    private static bool Covers(AttributePath p, ushort endpointId, uint clusterId) =>
        (p.Endpoint is null || p.Endpoint == endpointId) && (p.Cluster is null || p.Cluster == clusterId);

    private ushort NextExchangeId()
    {
        lock (_subGate) return _exchangeCounter++;
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
                    _options.FabricStore?.Save(_fabrics.All); // persist so the pairing survives restarts
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
            // Echo the initiator's ephemeral source node id as our destination so it can match the reply to
            // its unsecured session (required by strict commissioners e.g. Apple Home; matter.js is lenient).
            DestinationNodeId = request.SourceNodeId,
            Payload = payload,
        };
        return reply.Encode();
    }

    // Per Matter §4.5.1.1 the unsecured (global) message counter starts at a random value.
    private uint _unsecuredCounter = System.BitConverter.ToUInt32(System.Security.Cryptography.RandomNumberGenerator.GetBytes(4));
    private uint NextUnsecuredCounter() => _unsecuredCounter++;
}

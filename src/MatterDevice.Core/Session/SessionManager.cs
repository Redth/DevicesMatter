using System.Security.Cryptography;

namespace MatterDevice.Core.Session;

/// <summary>
/// Holds the device's active secure sessions, keyed by the <b>local</b> session id (the id the device
/// allocated and the peer stamps into messages sent to us). Allocates non-zero session ids; session id 0
/// is reserved for the unsecured session.
/// </summary>
public sealed class SessionManager
{
    private readonly Dictionary<ushort, SecureSession> _sessions = [];
    private readonly Lock _gate = new();

    /// <summary>Upper bound on concurrent secure sessions; the least-recently-active are evicted past this.
    /// Bounds the leak where each controller reconnect would otherwise add a session that never goes away.</summary>
    private const int MaxSessions = 48;

    /// <summary>Allocates an unused non-zero local session id.</summary>
    public ushort AllocateLocalSessionId()
    {
        lock (_gate)
        {
            for (var attempt = 0; attempt < 0x1_0000; attempt++)
            {
                var id = (ushort)(BitConverter.ToUInt16(RandomNumberGenerator.GetBytes(2)) | 1);
                if (id != 0 && !_sessions.ContainsKey(id))
                    return id;
            }
            throw new InvalidOperationException("Session id space exhausted.");
        }
    }

    /// <summary>Adds a session; if that pushes past <see cref="MaxSessions"/>, evicts the least-recently-active
    /// (never the one just added). Returns the evicted sessions so the caller can drop their subscriptions.</summary>
    public IReadOnlyList<SecureSession> Add(SecureSession session)
    {
        lock (_gate)
        {
            _sessions[session.LocalSessionId] = session;
            if (_sessions.Count <= MaxSessions) return [];
            var evicted = _sessions.Values
                .Where(s => s.LocalSessionId != session.LocalSessionId)
                .OrderBy(s => s.LastActivityUtc)
                .Take(_sessions.Count - MaxSessions)
                .ToList();
            foreach (var s in evicted) _sessions.Remove(s.LocalSessionId);
            return evicted;
        }
    }

    /// <summary>Removes any other sessions for the same peer node id — called when a controller re-establishes
    /// CASE, so reconnects <em>replace</em> the prior session instead of piling up. Returns the evicted.</summary>
    public IReadOnlyList<SecureSession> EvictPeer(ulong peerNodeId, ushort exceptLocalId)
    {
        if (peerNodeId == 0) return [];
        lock (_gate)
        {
            var evicted = _sessions.Values
                .Where(s => s.LocalSessionId != exceptLocalId && s.PeerNodeId == peerNodeId)
                .ToList();
            foreach (var s in evicted) _sessions.Remove(s.LocalSessionId);
            return evicted;
        }
    }

    /// <summary>Removes sessions with no inbound traffic for longer than <paramref name="idle"/> (dead
    /// controllers that never said goodbye). Returns the evicted so the caller can drop their subscriptions.</summary>
    public IReadOnlyList<SecureSession> EvictIdle(TimeSpan idle)
    {
        var cutoff = DateTime.UtcNow - idle;
        lock (_gate)
        {
            var evicted = _sessions.Values.Where(s => s.LastActivityUtc < cutoff).ToList();
            foreach (var s in evicted) _sessions.Remove(s.LocalSessionId);
            return evicted;
        }
    }

    public SecureSession? Find(ushort localSessionId)
    {
        lock (_gate)
            return _sessions.GetValueOrDefault(localSessionId);
    }

    public void Remove(ushort localSessionId)
    {
        lock (_gate)
            _sessions.Remove(localSessionId);
    }

    public IReadOnlyCollection<SecureSession> Active
    {
        get { lock (_gate) return _sessions.Values.ToList(); }
    }
}

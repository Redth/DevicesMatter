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

    public void Add(SecureSession session)
    {
        lock (_gate)
            _sessions[session.LocalSessionId] = session;
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

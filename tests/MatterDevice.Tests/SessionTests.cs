using MatterDevice.Core.Session;

namespace MatterDevice.Tests;

/// <summary>
/// Covers the secure-session bookkeeping CASE and the encrypted transport rely on: message-counter
/// de-duplication (the 32-entry sliding window, Matter Core Spec §4.6.7) and session-id allocation.
/// </summary>
public class SessionTests
{
    [Fact]
    public async Task Outbound_counter_is_unique_under_concurrent_encode()
    {
        // Encode runs concurrently (receive thread response + async subscription-report tasks). A
        // non-atomic counter would hand two messages the same value, the peer dedups, and a response is
        // silently dropped. Assert every counter from many parallel callers is distinct.
        var session = new SecureSession { LocalSessionId = 1, PeerSessionId = 2, DecryptKey = new byte[16], EncryptKey = new byte[16] };
        const int total = 50_000;
        var counters = new uint[total];
        await Parallel.ForEachAsync(Enumerable.Range(0, total), (i, _) =>
        {
            counters[i] = session.NextOutboundCounter();
            return ValueTask.CompletedTask;
        });
        Assert.Equal(total, counters.Distinct().Count());
    }

    [Fact]
    public void Reception_window_accepts_new_and_rejects_replays()
    {
        var state = new MessageReceptionState();

        Assert.Equal(MessageReceptionState.Result.Accepted, state.Process(100)); // first
        Assert.Equal(MessageReceptionState.Result.Accepted, state.Process(101)); // newer
        Assert.Equal(MessageReceptionState.Result.Duplicate, state.Process(101)); // exact replay
        Assert.Equal(MessageReceptionState.Result.Accepted, state.Process(105)); // jump forward
        Assert.Equal(MessageReceptionState.Result.Accepted, state.Process(103)); // within window, unseen
        Assert.Equal(MessageReceptionState.Result.Duplicate, state.Process(103)); // now a replay
        Assert.Equal(MessageReceptionState.Result.Accepted, state.Process(104)); // within window, unseen
    }

    [Fact]
    public void Reception_window_rejects_too_old()
    {
        var state = new MessageReceptionState();
        state.Process(1000);
        Assert.Equal(MessageReceptionState.Result.TooOld, state.Process(900)); // far outside the 32-window
    }

    [Fact]
    public void SessionManager_allocates_nonzero_ids_unique_among_live_sessions()
    {
        // The allocator picks a *random* non-zero id and guarantees only that it doesn't collide with a
        // currently-live session. Reusing an id after its session was evicted is fine — a stale retransmit
        // aimed at it fails to decrypt under the new session's keys. So we assert that live contract at every
        // step; asserting global uniqueness across evictions (as this test used to) can't hold for a random
        // allocator and made it flaky: past ~48 live sessions the cap evicts old ones, freeing their ids to
        // be drawn again, and 200 draws from the ~15-bit odd-id space collide by the birthday bound ~1 in 3.
        var mgr = new SessionManager();
        for (var i = 0; i < 200; i++)
        {
            var id = mgr.AllocateLocalSessionId();
            Assert.NotEqual(0, id);
            Assert.Null(mgr.Find(id)); // never hands out an id already in use by a live session
            mgr.Add(new SecureSession
            {
                LocalSessionId = id,
                PeerSessionId = 1,
                DecryptKey = new byte[16],
                EncryptKey = new byte[16],
            });
        }
        // The manager caps concurrent sessions (evicting the least-recently-active) so they never leak
        // unboundedly, and every live session has a distinct id.
        var live = mgr.Active.Select(s => s.LocalSessionId).ToList();
        Assert.InRange(live.Count, 1, 48);
        Assert.Equal(live.Count, live.Distinct().Count());
    }

    [Fact]
    public void SessionManager_evicts_prior_session_for_the_same_peer_on_reconnect()
    {
        var mgr = new SessionManager();
        SecureSession Make(ushort id, ulong peer) => new()
        {
            LocalSessionId = id, PeerSessionId = 1, PeerNodeId = peer,
            DecryptKey = new byte[16], EncryptKey = new byte[16],
        };
        mgr.Add(Make(10, peer: 0xAAAA));
        mgr.Add(Make(11, peer: 0xBBBB));
        // Peer 0xAAAA reconnects with a fresh session — its old one (10) must be evicted, not left to leak.
        mgr.Add(Make(12, peer: 0xAAAA));
        var evicted = mgr.EvictPeer(0xAAAA, exceptLocalId: 12);
        Assert.Contains(evicted, s => s.LocalSessionId == 10);
        Assert.Null(mgr.Find(10));
        Assert.NotNull(mgr.Find(12)); // the new one survives
        Assert.NotNull(mgr.Find(11)); // the other peer is untouched
    }

    [Fact]
    public void SessionManager_reaps_idle_sessions()
    {
        var mgr = new SessionManager();
        mgr.Add(new SecureSession { LocalSessionId = 7, PeerSessionId = 1, DecryptKey = new byte[16], EncryptKey = new byte[16] });
        Assert.Empty(mgr.EvictIdle(TimeSpan.FromMinutes(5)));   // fresh — not idle
        Assert.Single(mgr.EvictIdle(TimeSpan.FromMilliseconds(-1))); // everything older than "now+" → reaped
        Assert.Null(mgr.Find(7));
    }
}

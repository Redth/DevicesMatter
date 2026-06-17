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
    public void SessionManager_allocates_unique_nonzero_ids()
    {
        var mgr = new SessionManager();
        var ids = new HashSet<ushort>();
        for (var i = 0; i < 200; i++)
        {
            var id = mgr.AllocateLocalSessionId();
            Assert.NotEqual(0, id);
            mgr.Add(new SecureSession
            {
                LocalSessionId = id,
                PeerSessionId = 1,
                DecryptKey = new byte[16],
                EncryptKey = new byte[16],
            });
            Assert.True(ids.Add(id), "duplicate session id allocated");
        }
        Assert.Equal(200, mgr.Active.Count);
    }
}

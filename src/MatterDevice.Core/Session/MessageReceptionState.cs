namespace MatterDevice.Core.Session;

/// <summary>
/// Per-session message-counter reception state for de-duplication (Matter Core Spec §4.6.7): the highest
/// counter seen plus a 32-entry sliding window of recently-seen older counters. Duplicates are still
/// acknowledged by the caller (so the peer stops retransmitting) but not re-delivered.
/// </summary>
public sealed class MessageReceptionState
{
    private const int WindowSize = 32; // MSG_COUNTER_WINDOW_SIZE

    private uint _maxCounter;
    private uint _windowBitmap; // bit i set => (maxCounter - 1 - i) was seen
    private bool _initialized;

    public enum Result { Accepted, Duplicate, TooOld }

    /// <summary>Classifies <paramref name="counter"/> and, if accepted, records it.</summary>
    public Result Process(uint counter)
    {
        if (!_initialized)
        {
            _initialized = true;
            _maxCounter = counter;
            return Result.Accepted;
        }

        if (counter == _maxCounter)
            return Result.Duplicate;

        if (IsNewer(counter, _maxCounter))
        {
            var delta = counter - _maxCounter;
            // shift window left by delta, marking the old max as seen
            _windowBitmap = delta >= WindowSize ? 0u : (_windowBitmap << (int)delta) | (1u << (int)(delta - 1));
            _maxCounter = counter;
            return Result.Accepted;
        }

        // counter is older than max
        var back = _maxCounter - counter; // 1.._
        if (back > WindowSize)
            return Result.TooOld;
        var mask = 1u << (int)(back - 1);
        if ((_windowBitmap & mask) != 0)
            return Result.Duplicate;
        _windowBitmap |= mask;
        return Result.Accepted;
    }

    // True if a is strictly newer than b in unsigned 32-bit counter space (handles wrap).
    private static bool IsNewer(uint a, uint b) => (uint)(a - b) < 0x8000_0000u && a != b;
}

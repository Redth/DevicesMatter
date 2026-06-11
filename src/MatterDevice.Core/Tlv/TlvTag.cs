namespace MatterDevice.Core.Tlv;

/// <summary>
/// A TLV element tag. The spike only needs the two forms Matter's commissioning and interaction-model
/// payloads use: <see cref="Anonymous"/> (container elements) and <see cref="ContextSpecific"/> (struct
/// field numbers). Profile-specific / fully-qualified tags are deferred.
/// </summary>
public readonly struct TlvTag
{
    private TlvTag(bool anonymous, int tagNumber)
    {
        IsAnonymous = anonymous;
        TagNumber = tagNumber;
    }

    public bool IsAnonymous { get; }
    public bool IsContextSpecific => !IsAnonymous;

    /// <summary>Context-specific tag number (0–255). Meaningless when <see cref="IsAnonymous"/>.</summary>
    public int TagNumber { get; }

    /// <summary>An anonymous tag (used for the elements of arrays/lists and for top-level structures).</summary>
    public static TlvTag Anonymous { get; } = new(true, 0);

    /// <summary>A context-specific tag with the given field number.</summary>
    public static TlvTag ContextSpecific(int tagNumber)
    {
        if (tagNumber is < 0 or > 255)
            throw new ArgumentOutOfRangeException(nameof(tagNumber), "Context tag must be 0–255.");
        return new TlvTag(false, tagNumber);
    }
}

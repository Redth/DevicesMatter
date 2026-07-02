namespace MatterDevice.DataModel.Clusters;

/// <summary>
/// The Fan Control cluster (id 0x0202) — a variable-speed fan (Matter Application Cluster Spec §4.4). The
/// two attributes a controller drives are <see cref="Mode"/> (off / low / med / high / on) and
/// <see cref="PercentSetting"/> (0-100 target speed); the device reports back <see cref="PercentCurrent"/>.
/// Apple/Google Home render this as a fan with an on/off toggle and a speed slider.
/// </summary>
public sealed class FanControlCluster : Cluster
{
    public const uint ClusterId = 0x0202;
    public const uint FanModeId = 0x0000;
    public const uint FanModeSequenceId = 0x0001;
    public const uint PercentSettingId = 0x0002;
    public const uint PercentCurrentId = 0x0003;

    public FanControlCluster() : base(ClusterId, "Fan Control")
    {
        FeatureMap = 0; // percent-only — no MultiSpeed / Auto / Rocking / Wind features
        Set(FanModeId, (byte)FanMode.Off);
        Set(FanModeSequenceId, (byte)FanModeSequence.OffLowMedHigh);
        Set(PercentSettingId, (byte)0);
        Set(PercentCurrentId, (byte)0);
        // A controller sets the mode (on/off) and the target speed percent.
        MarkWritable(FanModeId, PercentSettingId);
    }

    /// <summary>Validates writes: the target percent must be 0-100.</summary>
    public override WriteStatus WriteAttribute(uint attributeId, object? value)
    {
        if (attributeId == PercentSettingId && Convert.ToInt64(value) is < 0 or > 100)
            return WriteStatus.ConstraintError;
        return base.WriteAttribute(attributeId, value);
    }

    public FanMode Mode
    {
        get => (FanMode)(byte)(Get(FanModeId) ?? (byte)0);
        set => SetAttribute(FanModeId, (byte)value);
    }

    /// <summary>Target speed, 0-100 percent.</summary>
    public byte PercentSetting
    {
        get => (byte)(Get(PercentSettingId) ?? (byte)0);
        set => SetAttribute(PercentSettingId, value);
    }

    /// <summary>Reported current speed, 0-100 percent.</summary>
    public byte PercentCurrent
    {
        get => (byte)(Get(PercentCurrentId) ?? (byte)0);
        set => SetAttribute(PercentCurrentId, value);
    }
}

/// <summary>Fan Control FanMode enum (Matter §4.4.5.1).</summary>
public enum FanMode : byte
{
    Off = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    On = 4,
    Auto = 5,
    Smart = 6,
}

/// <summary>Fan Control FanModeSequence enum — which modes the fan offers (Matter §4.4.5.2).</summary>
public enum FanModeSequence : byte
{
    OffLowMedHigh = 0,
    OffLowHigh = 1,
    OffLowMedHighAuto = 2,
    OffLowHighAuto = 3,
    OffHighAuto = 4,
    OffHigh = 5,
}

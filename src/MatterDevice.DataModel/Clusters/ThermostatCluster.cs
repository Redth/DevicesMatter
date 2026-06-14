namespace MatterDevice.DataModel.Clusters;

/// <summary>
/// The Thermostat cluster (id 0x0201) — the device type a pool heater maps to. Only the handful of
/// attributes needed to model a heater are surfaced here; the full cluster (and its setpoint commands)
/// land with the Interaction Model milestone.
/// </summary>
public sealed class ThermostatCluster : Cluster
{
    public const uint ClusterId = 0x0201;

    // Attribute IDs (Matter Application Cluster Spec, Thermostat).
    public const uint LocalTemperatureId = 0x0000;
    public const uint AbsMinHeatSetpointLimitId = 0x0003;
    public const uint AbsMaxHeatSetpointLimitId = 0x0004;
    public const uint OccupiedCoolingSetpointId = 0x0011;
    public const uint OccupiedHeatingSetpointId = 0x0012;
    public const uint MinHeatSetpointLimitId = 0x0015;
    public const uint MaxHeatSetpointLimitId = 0x0016;
    public const uint ControlSequenceOfOperationId = 0x001B;
    public const uint SystemModeId = 0x001C;

    // Heat setpoint range the device honors (centi-°C); matches the WriteAttribute clamp below.
    private const short MinHeatCentiC = 500;  //  5.00 °C
    private const short MaxHeatCentiC = 3500;  // 35.00 °C

    public ThermostatCluster() : base(ClusterId, "Thermostat")
    {
        FeatureMap = 0x01; // Heating — makes OccupiedHeatingSetpoint feature-conformant
        LocalTemperatureCentiC = 0;
        OccupiedHeatingSetpointCentiC = 2000; // 20.00 °C

        // Mandatory attributes that controllers rely on. Apple Home, in particular, only enables the
        // Off/Heat mode control — and actually writes SystemMode — when ControlSequenceOfOperation is
        // present; without it the mode toggle is inert (the temperature dial still works). The heat
        // setpoint limits bound that dial.
        Set(AbsMinHeatSetpointLimitId, MinHeatCentiC);
        Set(AbsMaxHeatSetpointLimitId, MaxHeatCentiC);
        Set(MinHeatSetpointLimitId, MinHeatCentiC);
        Set(MaxHeatSetpointLimitId, MaxHeatCentiC);
        Set(ControlSequenceOfOperationId, (byte)ThermostatControlSequence.HeatingOnly);

        SystemMode = ThermostatSystemMode.Heat;
        // A controller may set the heating setpoint and the system mode.
        MarkWritable(OccupiedHeatingSetpointId, SystemModeId);
    }

    /// <summary>Validates writes: the heating setpoint must be a sane 5–35 °C (500–3500 centi-°C).</summary>
    public override WriteStatus WriteAttribute(uint attributeId, object? value)
    {
        if (attributeId == OccupiedHeatingSetpointId &&
            Convert.ToInt64(value) is < 500 or > 3500)
            return WriteStatus.ConstraintError;
        return base.WriteAttribute(attributeId, value);
    }

    /// <summary>Measured temperature in 0.01 °C units.</summary>
    public short LocalTemperatureCentiC
    {
        get => (short)(Get(LocalTemperatureId) ?? (short)0);
        set => Set(LocalTemperatureId, value);
    }

    /// <summary>Heating setpoint in 0.01 °C units.</summary>
    public short OccupiedHeatingSetpointCentiC
    {
        get => (short)(Get(OccupiedHeatingSetpointId) ?? (short)0);
        set => Set(OccupiedHeatingSetpointId, value);
    }

    public ThermostatSystemMode SystemMode
    {
        get => (ThermostatSystemMode)(byte)(Get(SystemModeId) ?? (byte)0);
        set => Set(SystemModeId, (byte)value);
    }
}

/// <summary>Thermostat SystemMode enum (subset).</summary>
public enum ThermostatSystemMode : byte
{
    Off = 0,
    Auto = 1,
    Cool = 3,
    Heat = 4,
}

/// <summary>Thermostat ControlSequenceOfOperation enum (subset) — which heating/cooling modes the unit runs.</summary>
public enum ThermostatControlSequence : byte
{
    CoolingOnly = 0,
    HeatingOnly = 2,
    CoolingAndHeating = 4,
}

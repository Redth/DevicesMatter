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
    public const uint OccupiedCoolingSetpointId = 0x0011;
    public const uint OccupiedHeatingSetpointId = 0x0012;
    public const uint SystemModeId = 0x001C;

    public ThermostatCluster() : base(ClusterId, "Thermostat")
    {
        LocalTemperatureCentiC = 0;
        OccupiedHeatingSetpointCentiC = 2000; // 20.00 °C
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

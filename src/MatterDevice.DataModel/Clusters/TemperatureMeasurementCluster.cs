namespace MatterDevice.DataModel.Clusters;

/// <summary>
/// The Temperature Measurement cluster (id 0x0402) — a read-only temperature sensor (Matter Application
/// Cluster Spec §2.3). <see cref="MeasuredValueCentiC"/> is the temperature in 0.01 °C units; the device
/// pushes updates via <see cref="Cluster.SetAttribute"/> and controllers subscribe to it. Pair it with the
/// <c>TemperatureSensor</c> device type (0x0302) so ecosystems render it as a temperature sensor.
/// </summary>
public sealed class TemperatureMeasurementCluster : Cluster
{
    public const uint ClusterId = 0x0402;
    public const uint MeasuredValueId = 0x0000;
    public const uint MinMeasuredValueId = 0x0001;
    public const uint MaxMeasuredValueId = 0x0002;

    /// <param name="minCentiC">Lowest value the sensor can report (default −40.00 °C).</param>
    /// <param name="maxCentiC">Highest value the sensor can report (default 125.00 °C).</param>
    public TemperatureMeasurementCluster(short minCentiC = -4000, short maxCentiC = 12500)
        : base(ClusterId, "Temperature Measurement")
    {
        Set(MeasuredValueId, (short)0);
        Set(MinMeasuredValueId, minCentiC);
        Set(MaxMeasuredValueId, maxCentiC);
    }

    /// <summary>Measured temperature in 0.01 °C units (e.g. 2340 = 23.40 °C).</summary>
    public short MeasuredValueCentiC
    {
        get => (short)(Get(MeasuredValueId) ?? (short)0);
        set => SetAttribute(MeasuredValueId, value);
    }
}

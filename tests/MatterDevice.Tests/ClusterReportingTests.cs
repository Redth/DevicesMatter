using MatterDevice.DataModel;
using MatterDevice.DataModel.Clusters;

namespace MatterDevice.Tests;

/// <summary>
/// Guards the rule that makes live device state actually reach a controller: a cluster property that models
/// device state must notify subscribers when set. The base class offers two setters — the silent
/// <c>Set</c> (constructor seeding only) and <c>SetAttribute</c> (bumps DataVersion, raises
/// AttributeChanged, which the node turns into a proactive report). A property wired to the silent one
/// looks completely correct — it stores, reads back, and answers ReadRequests — while the ecosystem shows
/// stale state forever. That is not a failure any ordinary test catches, hence this sweep.
/// </summary>
public class ClusterReportingTests
{
    /// <summary>One instance of every cluster that carries settable state.</summary>
    private static IEnumerable<Cluster> AllClusters() =>
    [
        new ThermostatCluster(),
        new OnOffCluster(),
        new FanControlCluster(),
        new TemperatureMeasurementCluster(),
        new GeneralCommissioningCluster(),
        new AccessControlCluster(),
        new OperationalCredentialsCluster(),
        new BasicInformationCluster(0xFFF1, "vendor", 0x8001, "product", "unique-id"),
        new BridgedDeviceBasicInformationCluster("label", "vendor", "product", "unique-id"),
    ];

    [Fact]
    public void Every_settable_cluster_property_reports_the_change()
    {
        var checkedProperties = 0;
        foreach (var cluster in AllClusters())
        {
            // Only properties declared by the concrete cluster: the base class's ClusterRevision/FeatureMap
            // are static metadata, not live state, and are deliberately silent.
            var properties = cluster.GetType()
                .GetProperties()
                .Where(p => p.DeclaringType == cluster.GetType() && p.CanRead && p.CanWrite && p.SetMethod?.IsPublic == true);

            foreach (var property in properties)
            {
                var changed = new List<uint>();
                void OnChanged(Cluster _, uint id) => changed.Add(id);
                cluster.AttributeChanged += OnChanged;
                try
                {
                    // SetAttribute short-circuits when the value is unchanged, so write something different.
                    property.SetValue(cluster, DifferentValueFor(property.PropertyType, property.GetValue(cluster), property.Name));
                }
                finally
                {
                    cluster.AttributeChanged -= OnChanged;
                }

                Assert.True(changed.Count > 0,
                    $"{cluster.GetType().Name}.{property.Name} did not raise AttributeChanged — its setter must use " +
                    "SetAttribute, not the silent Set, or controllers will never see the change.");
                checkedProperties++;
            }
        }

        Assert.True(checkedProperties >= 12, $"expected to sweep the known settable properties, only saw {checkedProperties}");
    }

    /// <summary>A value guaranteed to differ from <paramref name="current"/>, so the set is a real change.</summary>
    private static object DifferentValueFor(Type type, object? current, string propertyName)
    {
        var underlying = Nullable.GetUnderlyingType(type) ?? type;

        if (underlying == typeof(string)) return (current as string) == "changed" ? "changed-again" : "changed";
        if (underlying == typeof(bool)) return !(bool)(current ?? false);
        if (underlying.IsEnum)
            return Enum.GetValues(underlying).Cast<object>().First(v => !Equals(v, current));
        if (underlying == typeof(byte)) return (byte)(((byte)(current ?? (byte)0)) + 1);
        if (underlying == typeof(short)) return (short)(((short)(current ?? (short)0)) + 1);
        if (underlying == typeof(ushort)) return (ushort)(((ushort)(current ?? (ushort)0)) + 1);
        if (underlying == typeof(uint)) return (uint)(current ?? 0u) + 1u;
        if (underlying == typeof(ulong)) return (ulong)(current ?? 0UL) + 1UL;

        // Fail loudly rather than skipping: an unhandled type would silently shrink this guard's coverage.
        throw new NotSupportedException($"Add a distinct-value case for {underlying.Name} (property {propertyName}).");
    }

    [Fact]
    public void Constructor_seeding_stays_silent()
    {
        // The flip side of the rule: building a cluster must not raise change events (nothing is subscribed
        // yet, and seeding is not a change). Wiring a constructor to SetAttribute would report phantom
        // changes for every attribute at startup.
        var raised = 0;
        var thermostat = new ThermostatCluster();
        thermostat.AttributeChanged += (_, _) => raised++;
        Assert.Equal(0, raised);

        // ...but the very next real update does report.
        thermostat.LocalTemperatureCentiC = 1234;
        Assert.Equal(1, raised);
    }
}

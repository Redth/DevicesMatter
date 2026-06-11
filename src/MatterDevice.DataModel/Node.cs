namespace MatterDevice.DataModel;

/// <summary>
/// A Matter node's data model: a tree of endpoints, each exposing clusters of attributes/commands
/// (Matter Core Spec §7, "Data Model"). This is a minimal skeleton — enough to describe a Thermostat
/// node and the bridge Aggregator shape — without the Interaction Model wire handling (Read/Subscribe/
/// Invoke), which is the next milestone after commissioning. See <c>docs/00-feasibility.md</c>.
/// </summary>
public sealed class Node
{
    private readonly List<Endpoint> _endpoints = [];
    public IReadOnlyList<Endpoint> Endpoints => _endpoints;

    public Endpoint AddEndpoint(ushort id, DeviceType deviceType)
    {
        var ep = new Endpoint(id, deviceType);
        _endpoints.Add(ep);
        return ep;
    }
}

/// <summary>A Matter endpoint: a numbered container of clusters realizing one device type.</summary>
public sealed class Endpoint(ushort id, DeviceType deviceType)
{
    private readonly List<Cluster> _clusters = [];

    public ushort Id { get; } = id;
    public DeviceType DeviceType { get; } = deviceType;
    public IReadOnlyList<Cluster> Clusters => _clusters;

    public Endpoint AddCluster(Cluster cluster)
    {
        _clusters.Add(cluster);
        return this;
    }
}

/// <summary>A Matter device type identifier (Matter Device Library).</summary>
public readonly record struct DeviceType(uint Id, string Name)
{
    public static readonly DeviceType RootNode = new(0x0016, "Root Node");
    public static readonly DeviceType Aggregator = new(0x000E, "Aggregator");
    public static readonly DeviceType BridgedNode = new(0x0013, "Bridged Node");
    public static readonly DeviceType Thermostat = new(0x0301, "Thermostat");
    public static readonly DeviceType TemperatureSensor = new(0x0302, "Temperature Sensor");
}

/// <summary>Base for a cluster: a numbered set of attributes (and, later, commands/events).</summary>
public abstract class Cluster(uint id, string name)
{
    private readonly Dictionary<uint, object?> _attributes = [];

    public uint Id { get; } = id;
    public string Name { get; } = name;
    public IReadOnlyDictionary<uint, object?> Attributes => _attributes;

    protected void Set(uint attributeId, object? value) => _attributes[attributeId] = value;
    public object? Get(uint attributeId) => _attributes.GetValueOrDefault(attributeId);
}

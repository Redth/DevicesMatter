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

    /// <summary>
    /// Adds a Descriptor cluster to every endpoint (call after all other clusters are set up). The root
    /// endpoint's Descriptor lists the child endpoints in its PartsList. Required for a commissioner to
    /// enumerate the node.
    /// </summary>
    public void AddDescriptors()
    {
        var childEndpoints = _endpoints.Where(e => e.Id != 0).Select(e => e.Id).ToList();
        foreach (var ep in _endpoints)
        {
            IReadOnlyList<ushort> parts = ep.Id == 0 ? childEndpoints : [];
            ep.AddCluster(new Clusters.DescriptorCluster(ep, parts));
        }
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

/// <summary>
/// Base for a cluster: a numbered set of attributes plus the Matter global attributes every cluster
/// exposes (FeatureMap, ClusterRevision, and the AttributeList/AcceptedCommandList/GeneratedCommandList
/// that a commissioner reads to learn the cluster's shape — Matter Core Spec §7.13).
/// </summary>
public abstract class Cluster(uint id, string name)
{
    public const uint GeneratedCommandListId = 0xFFF8;
    public const uint AcceptedCommandListId = 0xFFF9;
    public const uint EventListId = 0xFFFA;
    public const uint AttributeListId = 0xFFFB;
    public const uint FeatureMapId = 0xFFFC;
    public const uint ClusterRevisionId = 0xFFFD;

    private readonly Dictionary<uint, object?> _attributes = [];

    public uint Id { get; } = id;
    public string Name { get; } = name;
    public ushort ClusterRevision { get; set; } = 1;
    public uint FeatureMap { get; set; }
    protected uint[] AcceptedCommands { get; set; } = [];
    protected uint[] GeneratedCommands { get; set; } = [];

    protected void Set(uint attributeId, object? value) => _attributes[attributeId] = value;

    public object? Get(uint attributeId) => attributeId switch
    {
        FeatureMapId => FeatureMap,
        ClusterRevisionId => ClusterRevision,
        AttributeListId => new TlvArray(AttributeIds().Select(object (a) => (ulong)a)),
        AcceptedCommandListId => new TlvArray(AcceptedCommands.Select(object (c) => (ulong)c)),
        GeneratedCommandListId => new TlvArray(GeneratedCommands.Select(object (c) => (ulong)c)),
        EventListId => new TlvArray(),
        _ => _attributes.GetValueOrDefault(attributeId),
    };

    /// <summary>Every readable attribute id (cluster-specific + globals), used for wildcard reads and AttributeList.</summary>
    public IReadOnlyDictionary<uint, object?> Attributes
    {
        get
        {
            var all = new Dictionary<uint, object?>();
            foreach (var id in AttributeIds())
                all[id] = Get(id);
            return all;
        }
    }

    private IEnumerable<uint> AttributeIds() =>
        _attributes.Keys.Concat([FeatureMapId, ClusterRevisionId, AttributeListId,
            AcceptedCommandListId, GeneratedCommandListId, EventListId]);
}

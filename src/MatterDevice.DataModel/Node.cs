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
    private readonly List<DeviceType> _deviceTypes = [deviceType];

    public ushort Id { get; } = id;
    public DeviceType DeviceType { get; } = deviceType;

    /// <summary>All device types this endpoint realizes (e.g. a bridged thermostat is [Bridged Node, Thermostat]).</summary>
    public IReadOnlyList<DeviceType> DeviceTypes => _deviceTypes;
    public IReadOnlyList<Cluster> Clusters => _clusters;

    public Endpoint AddCluster(Cluster cluster)
    {
        _clusters.Add(cluster);
        return this;
    }

    /// <summary>Adds an additional device type to this endpoint's Descriptor (e.g. Bridged Node for a bridged device).</summary>
    public Endpoint AddDeviceType(DeviceType deviceType)
    {
        _deviceTypes.Add(deviceType);
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
    public static readonly DeviceType OnOffPlugInUnit = new(0x010A, "On/Off Plug-in Unit");
    public static readonly DeviceType Pump = new(0x0303, "Pump");
    public static readonly DeviceType Fan = new(0x002B, "Fan");
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
    private readonly HashSet<uint> _writable = [];

    public uint Id { get; } = id;
    public string Name { get; } = name;
    public ushort ClusterRevision { get; set; } = 1;
    public uint FeatureMap { get; set; }
    protected uint[] AcceptedCommands { get; set; } = [];
    protected uint[] GeneratedCommands { get; set; } = [];

    /// <summary>Increments on any attribute change; controllers use it for subscription/report dedup.</summary>
    public uint DataVersion { get; private set; } = 1;

    /// <summary>Raised when an attribute value changes (carries the changed attribute id).</summary>
    public event Action<Cluster, uint>? AttributeChanged;

    /// <summary>Sets an attribute's initial value (no change event; for construction).</summary>
    protected void Set(uint attributeId, object? value) => _attributes[attributeId] = value;

    /// <summary>Marks an attribute writable by a controller (WriteRequest).</summary>
    protected void MarkWritable(params uint[] attributeIds)
    {
        foreach (var id in attributeIds) _writable.Add(id);
    }

    public bool IsWritable(uint attributeId) => _writable.Contains(attributeId);

    /// <summary>
    /// Sets an attribute and notifies subscribers (bumps <see cref="DataVersion"/> + raises
    /// <see cref="AttributeChanged"/>). Device code calls this to push live updates (sensor readings, etc.).
    /// </summary>
    public void SetAttribute(uint attributeId, object? value)
    {
        if (_attributes.TryGetValue(attributeId, out var existing) && Equals(existing, value))
            return;
        _attributes[attributeId] = value;
        DataVersion++;
        AttributeChanged?.Invoke(this, attributeId);
    }

    /// <summary>
    /// Applies a controller write to an attribute. Override to validate / react; the default accepts a
    /// write to any attribute marked <see cref="MarkWritable"/> and rejects the rest.
    /// </summary>
    public virtual WriteStatus WriteAttribute(uint attributeId, object? value)
    {
        if (!IsWritable(attributeId))
            return WriteStatus.UnsupportedWrite;
        SetAttribute(attributeId, CoerceToExisting(attributeId, value));
        return WriteStatus.Success;
    }

    /// <summary>Coerces an incoming write value to the existing attribute's CLR type (e.g. a TLV int → short).</summary>
    protected object? CoerceToExisting(uint attributeId, object? value)
    {
        if (value is null || _attributes.GetValueOrDefault(attributeId) is not { } existing)
            return value;
        var target = existing.GetType();
        if (value.GetType() == target)
            return value;
        try { return target.IsEnum ? Enum.ToObject(target, value) : Convert.ChangeType(value, target); }
        catch { return value; }
    }

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

/// <summary>Result of a controller attribute write (Matter Core Spec §8.10 status subset).</summary>
public enum WriteStatus : byte
{
    Success = 0x00,
    UnsupportedAttribute = 0x86,
    UnsupportedWrite = 0x88,
    ConstraintError = 0x87,
    InvalidValue = 0x89,
}

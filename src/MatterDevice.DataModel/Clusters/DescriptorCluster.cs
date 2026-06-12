namespace MatterDevice.DataModel.Clusters;

/// <summary>
/// The Descriptor cluster (id 0x001D) — describes an endpoint's device types, server/client clusters and,
/// on the root, the list of child endpoints (Matter Core Spec §9.5). A commissioner reads it to enumerate
/// the node. The lists are computed live from the endpoint so they always match what's actually present.
/// </summary>
public sealed class DescriptorCluster : Cluster
{
    public const uint ClusterId = 0x001D;

    public const uint DeviceTypeListId = 0x0000;
    public const uint ServerListId = 0x0001;
    public const uint ClientListId = 0x0002;
    public const uint PartsListId = 0x0003;

    public DescriptorCluster(Endpoint endpoint, IReadOnlyList<ushort> partsList) : base(ClusterId, "Descriptor")
    {
        // DeviceTypeList: array of { 0: deviceType, 1: revision } — all device types the endpoint realizes
        Set(DeviceTypeListId, new TlvArray(
            endpoint.DeviceTypes.Select(object (dt) => new TlvStruct().Add(0, (ulong)dt.Id).Add(1, (ushort)1))));
        // ServerList: every cluster present on this endpoint (plus this Descriptor, added last)
        Set(ServerListId, new TlvArray(endpoint.Clusters.Select(c => c.Id).Append(ClusterId).Distinct().Select(object (id) => (ulong)id)));
        Set(ClientListId, new TlvArray());
        // PartsList: child endpoints (non-empty only on the root)
        Set(PartsListId, new TlvArray(partsList.Select(object (e) => (ulong)e)));
    }
}

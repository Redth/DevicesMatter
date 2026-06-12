namespace MatterDevice.DataModel.Clusters;

/// <summary>
/// The Bridged Device Basic Information cluster (id 0x0039) — identifies a device exposed through a bridge
/// (Matter Core Spec §9.13). Its presence on an endpoint is how a controller recognizes a bridged device;
/// it mirrors a subset of Basic Information (name, vendor/product, reachability).
/// </summary>
public sealed class BridgedDeviceBasicInformationCluster : Cluster
{
    public const uint ClusterId = 0x0039;

    public const uint VendorNameId = 0x0001;
    public const uint ProductNameId = 0x0003;
    public const uint NodeLabelId = 0x0005;
    public const uint ReachableId = 0x0011;
    public const uint UniqueIdId = 0x0012;

    public BridgedDeviceBasicInformationCluster(string nodeLabel, string vendorName, string productName, string uniqueId, bool reachable = true)
        : base(ClusterId, "Bridged Device Basic Information")
    {
        Set(VendorNameId, vendorName);
        Set(ProductNameId, productName);
        Set(NodeLabelId, nodeLabel);
        Set(ReachableId, reachable);
        Set(UniqueIdId, uniqueId);
    }

    /// <summary>Whether the bridged device is currently reachable (update live as the backend connects/drops).</summary>
    public bool Reachable
    {
        get => (bool)(Get(ReachableId) ?? false);
        set => SetAttribute(ReachableId, value);
    }
}

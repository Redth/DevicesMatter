namespace MatterDevice.DataModel.Clusters;

/// <summary>
/// The Basic Information cluster (id 0x0028) on the root endpoint — vendor/product identity a commissioner
/// reads early in commissioning (Matter Core Spec §11.1). Scalar attributes only here; the full cluster
/// adds a capability struct and events.
/// </summary>
public sealed class BasicInformationCluster : Cluster
{
    public const uint ClusterId = 0x0028;

    public const uint DataModelRevisionId = 0x0000;
    public const uint VendorNameId = 0x0001;
    public const uint VendorIdId = 0x0002;
    public const uint ProductNameId = 0x0003;
    public const uint ProductIdId = 0x0004;
    public const uint NodeLabelId = 0x0005;
    public const uint HardwareVersionId = 0x0007;
    public const uint SoftwareVersionId = 0x0009;
    public const uint SoftwareVersionStringId = 0x000A;
    public const uint ReachableId = 0x0011;
    public const uint UniqueIdId = 0x0012;

    public BasicInformationCluster(ushort vendorId, string vendorName, ushort productId, string productName, string uniqueId)
        : base(ClusterId, "Basic Information")
    {
        Set(DataModelRevisionId, (ushort)ImConstantsRevision);
        Set(VendorNameId, vendorName);
        Set(VendorIdId, vendorId);
        Set(ProductNameId, productName);
        Set(ProductIdId, productId);
        Set(NodeLabelId, "");
        Set(HardwareVersionId, (ushort)1);
        Set(SoftwareVersionId, 1u);
        Set(SoftwareVersionStringId, "0.1.0");
        Set(ReachableId, true);
        Set(UniqueIdId, uniqueId);
    }

    private const int ImConstantsRevision = 17;

    public string? NodeLabel
    {
        get => (string?)Get(NodeLabelId);
        set => Set(NodeLabelId, value ?? "");
    }
}

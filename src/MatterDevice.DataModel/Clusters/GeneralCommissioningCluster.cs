namespace MatterDevice.DataModel.Clusters;

/// <summary>
/// The General Commissioning cluster (id 0x0030) on the root endpoint — drives the commissioning
/// fail-safe and completion (Matter Core Spec §11.9). The command handlers belong in the device's
/// commissioning state machine; this models the attributes and the command IDs.
/// </summary>
public sealed class GeneralCommissioningCluster : Cluster
{
    public const uint ClusterId = 0x0030;

    // Attributes
    public const uint BreadcrumbId = 0x0000;
    public const uint RegulatoryConfigId = 0x0002;
    public const uint LocationCapabilityId = 0x0003;
    public const uint SupportsConcurrentConnectionId = 0x0004;

    // Commands (request opcodes)
    public const uint ArmFailSafeId = 0x00;
    public const uint ArmFailSafeResponseId = 0x01;
    public const uint SetRegulatoryConfigId = 0x02;
    public const uint SetRegulatoryConfigResponseId = 0x03;
    public const uint CommissioningCompleteId = 0x04;
    public const uint CommissioningCompleteResponseId = 0x05;

    public GeneralCommissioningCluster() : base(ClusterId, "General Commissioning")
    {
        Set(BreadcrumbId, 0UL);
        Set(RegulatoryConfigId, (byte)RegulatoryLocationType.IndoorOutdoor);
        Set(LocationCapabilityId, (byte)RegulatoryLocationType.IndoorOutdoor);
        Set(SupportsConcurrentConnectionId, true);
    }

    /// <summary>Commissioning progress marker the commissioner sets on each step (Matter §11.9.6).</summary>
    public ulong Breadcrumb
    {
        get => (ulong)(Get(BreadcrumbId) ?? 0UL);
        set => Set(BreadcrumbId, value);
    }
}

/// <summary>Regulatory location type for General Commissioning.</summary>
public enum RegulatoryLocationType : byte
{
    Indoor = 0,
    Outdoor = 1,
    IndoorOutdoor = 2,
}

/// <summary>The CommissioningError code returned by General Commissioning command responses (Matter §11.9.5.1).</summary>
public enum CommissioningError : byte
{
    Ok = 0,
    ValueOutsideRange = 1,
    InvalidAuthentication = 2,
    NoFailSafe = 3,
    BusyWithOtherAdmin = 4,
}

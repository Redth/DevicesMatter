namespace MatterDevice.DataModel.Clusters;

/// <summary>
/// The Access Control cluster (id 0x001F) on the root endpoint — a commissioner writes the ACL during
/// commissioning to grant itself administer access (Matter Core Spec §9.10). This models the attributes
/// and accepts the ACL/Extension writes (stored verbatim); fine-grained ACL <em>enforcement</em> is a
/// follow-on. The cluster's presence + accepting the write is what a controller requires.
/// </summary>
public sealed class AccessControlCluster : Cluster
{
    public const uint ClusterId = 0x001F;

    public const uint AclId = 0x0000;
    public const uint ExtensionId = 0x0001;
    public const uint SubjectsPerEntryId = 0x0002;
    public const uint TargetsPerEntryId = 0x0003;
    public const uint EntriesPerFabricId = 0x0004;

    public AccessControlCluster() : base(ClusterId, "Access Control")
    {
        Set(AclId, new TlvArray());
        Set(ExtensionId, new TlvArray());
        Set(SubjectsPerEntryId, (ushort)4);
        Set(TargetsPerEntryId, (ushort)3);
        Set(EntriesPerFabricId, (ushort)4);
        MarkWritable(AclId, ExtensionId);
    }
}

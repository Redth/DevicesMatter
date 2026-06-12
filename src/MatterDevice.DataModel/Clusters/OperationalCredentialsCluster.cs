namespace MatterDevice.DataModel.Clusters;

/// <summary>
/// The Node Operational Credentials cluster (id 0x003E) as a readable cluster — a commissioner reads the
/// fabric counts and lists during commissioning (Matter Core Spec §11.17). The commands are executed by the
/// device's commissioning state machine; this models the attributes (and is updated as fabrics are added).
/// </summary>
public sealed class OperationalCredentialsCluster : Cluster
{
    public const uint ClusterId = 0x003E;

    public const uint NocsId = 0x0000;
    public const uint FabricsId = 0x0001;
    public const uint SupportedFabricsId = 0x0002;
    public const uint CommissionedFabricsId = 0x0003;
    public const uint TrustedRootCertificatesId = 0x0004;
    public const uint CurrentFabricIndexId = 0x0005;

    public OperationalCredentialsCluster() : base(ClusterId, "Operational Credentials")
    {
        Set(NocsId, new TlvArray());
        Set(FabricsId, new TlvArray());
        Set(SupportedFabricsId, (byte)16);
        Set(CommissionedFabricsId, (byte)0);
        Set(TrustedRootCertificatesId, new TlvArray());
        Set(CurrentFabricIndexId, (byte)0);
        AcceptedCommands = [0x00, 0x02, 0x04, 0x06, 0x07, 0x09, 0x0A, 0x0B];
        GeneratedCommands = [0x01, 0x03, 0x05, 0x08];
    }

    /// <summary>Reflects a newly-added fabric in the readable attributes.</summary>
    public void OnFabricAdded(byte fabricIndex)
    {
        Set(CommissionedFabricsId, fabricIndex);
        Set(CurrentFabricIndexId, fabricIndex);
    }
}

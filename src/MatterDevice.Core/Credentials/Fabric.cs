using MatterDevice.Core.Crypto;

namespace MatterDevice.Core.Credentials;

/// <summary>
/// A commissioned fabric the device belongs to: the trust root, the device's own NOC + operational key,
/// the fabric/node identifiers, the IPK, and the derived compressed-fabric-id and operational IPK that
/// CASE consumes. Built from the data delivered by <c>AddTrustedRootCertificate</c> + <c>AddNOC</c>.
/// </summary>
public sealed class Fabric
{
    public required byte FabricIndex { get; init; }
    public required ulong FabricId { get; init; }
    public required ulong NodeId { get; init; }
    public required MatterCertificate RootCertificate { get; init; }
    public required MatterCertificate Noc { get; init; }
    public MatterCertificate? Icac { get; init; }
    public required P256KeyPair OperationalKey { get; init; }

    /// <summary>The raw 16-byte IPK delivered in AddNOC (the epoch key).</summary>
    public required byte[] EpochIpk { get; init; }

    /// <summary>The 8-byte compressed fabric id (derived from the root public key + fabric id).</summary>
    public byte[] CompressedFabricId =>
        _compressed ??= FabricCrypto.CompressedFabricId(RootCertificate.EllipticCurvePublicKey, FabricId);
    private byte[]? _compressed;

    /// <summary>The 16-byte operational IPK CASE folds into its salts and destination id.</summary>
    public byte[] OperationalIpk =>
        _opIpk ??= FabricCrypto.OperationalIpk(EpochIpk, CompressedFabricId);
    private byte[]? _opIpk;

    public byte[] RootPublicKey => RootCertificate.EllipticCurvePublicKey;
}

/// <summary>Holds the device's commissioned fabrics, indexed by fabric index (Matter Core Spec §5.4.2).</summary>
public sealed class FabricTable
{
    private readonly Dictionary<byte, Fabric> _fabrics = [];
    private byte _nextIndex = 1;

    public byte Add(Func<byte, Fabric> build)
    {
        var index = _nextIndex++;
        _fabrics[index] = build(index);
        return index;
    }

    public Fabric? Get(byte fabricIndex) => _fabrics.GetValueOrDefault(fabricIndex);
    public IReadOnlyCollection<Fabric> All => _fabrics.Values;
    public int Count => _fabrics.Count;
}

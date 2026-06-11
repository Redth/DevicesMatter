using MatterDevice.Core.Credentials;
using MatterDevice.Core.Crypto;

namespace MatterDevice.Tests;

/// <summary>
/// Covers the Matter operational certificate codec and the chain it forms: a generated RCAC + NOC encode
/// to TLV and decode back losslessly (public key, node id, fabric id, extensions), the NOC's signature
/// verifies against the root, and tampering / wrong-fabric is rejected.
/// </summary>
public class CertificateTests
{
    private const ulong FabricId = 0xFAB000000000001D;
    private const ulong NodeId = 0x00000000DEDEDEDE;
    private const ulong RcacId = 0xCACACACA00000001;

    [Fact]
    public void Root_and_noc_round_trip_through_tlv()
    {
        var rootKey = P256KeyPair.Generate();
        var nodeKey = P256KeyPair.Generate();
        var root = OperationalCredentials.CreateRootCertificate(rootKey, RcacId);
        var noc = OperationalCredentials.CreateNodeCertificate(rootKey, root, nodeKey, FabricId, NodeId);

        var decodedNoc = MatterCertificate.Decode(noc.Encode());
        Assert.Equal(Convert.ToHexString(nodeKey.PublicKey), Convert.ToHexString(decodedNoc.EllipticCurvePublicKey));
        Assert.Equal(NodeId, decodedNoc.Subject.NodeId);
        Assert.Equal(FabricId, decodedNoc.Subject.FabricId);
        Assert.False(decodedNoc.Extensions.IsCa);
        Assert.Equal(20, decodedNoc.Extensions.SubjectKeyId!.Length);

        var decodedRoot = MatterCertificate.Decode(root.Encode());
        Assert.True(decodedRoot.Extensions.IsCa);
        Assert.Equal(RcacId, decodedRoot.Subject.RcacId);
    }

    [Fact]
    public void Noc_chains_to_root()
    {
        var rootKey = P256KeyPair.Generate();
        var nodeKey = P256KeyPair.Generate();
        var root = OperationalCredentials.CreateRootCertificate(rootKey, RcacId);
        var noc = OperationalCredentials.CreateNodeCertificate(rootKey, root, nodeKey, FabricId, NodeId);

        // round-trip through the wire, then validate
        var wireNoc = MatterCertificate.Decode(noc.Encode());
        var wireRoot = MatterCertificate.Decode(root.Encode());

        Assert.True(OperationalCredentials.ValidateChain(wireNoc, wireRoot, FabricId));
        Assert.False(OperationalCredentials.ValidateChain(wireNoc, wireRoot, FabricId + 1)); // wrong fabric
    }

    [Fact]
    public void Tampered_noc_fails_validation()
    {
        var rootKey = P256KeyPair.Generate();
        var otherRootKey = P256KeyPair.Generate();
        var nodeKey = P256KeyPair.Generate();
        var root = OperationalCredentials.CreateRootCertificate(rootKey, RcacId);
        var noc = OperationalCredentials.CreateNodeCertificate(rootKey, root, nodeKey, FabricId, NodeId);

        // a NOC signed by a different root must not validate against the real root
        var rogueRoot = OperationalCredentials.CreateRootCertificate(otherRootKey, RcacId);
        var rogueNoc = OperationalCredentials.CreateNodeCertificate(otherRootKey, rogueRoot, nodeKey, FabricId, NodeId);
        Assert.False(OperationalCredentials.VerifySignature(rogueNoc, root.EllipticCurvePublicKey));
        Assert.True(OperationalCredentials.VerifySignature(noc, root.EllipticCurvePublicKey));
    }
}

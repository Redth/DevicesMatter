using System.Security.Cryptography;
using MatterDevice.Commissioning.Case;
using MatterDevice.Core.Credentials;
using MatterDevice.Core.Crypto;

namespace MatterDevice.Tests;

/// <summary>
/// End-to-end CASE: a commissioner (initiator) harness drives the device <see cref="CaseResponder"/>
/// through Sigma1/2/3 over a shared fabric, and both sides must independently derive the SAME operational
/// session keys. This validates the whole CASE flow — destination-id fabric selection, ephemeral ECDH,
/// the S2K/S3K/SEK key schedule, the NOC signatures, and chain validation. A genuine controller runs the
/// same initiator role.
/// </summary>
public class CaseHandshakeTests
{
    private const ulong FabricId = 0xFAB000000000001D;
    private const ulong DeviceNodeId = 0x00000000DEDEDEDE;
    private const ulong CommissionerNodeId = 0x000000001234ABCD;
    private const ulong RcacId = 0xCACACACA00000001;

    [Fact]
    public void Full_case_handshake_yields_matching_session_keys()
    {
        // ----- a commissioned fabric (root + device NOC + commissioner NOC, shared IPK) -----
        var rootKey = P256KeyPair.Generate();
        var root = OperationalCredentials.CreateRootCertificate(rootKey, RcacId);
        var epochIpk = RandomNumberGenerator.GetBytes(16);

        var deviceKey = P256KeyPair.Generate();
        var deviceNoc = OperationalCredentials.CreateNodeCertificate(rootKey, root, deviceKey, FabricId, DeviceNodeId);

        var fabrics = new FabricTable();
        fabrics.Add(index => new Fabric
        {
            FabricIndex = index,
            FabricId = FabricId,
            NodeId = DeviceNodeId,
            RootCertificate = root,
            Noc = deviceNoc,
            OperationalKey = deviceKey,
            EpochIpk = epochIpk,
        });

        var device = new CaseResponder(fabrics, localSessionId: 0xA1A1);

        // commissioner identity on the same fabric
        var commissionerKey = P256KeyPair.Generate();
        var commissionerNoc = OperationalCredentials.CreateNodeCertificate(rootKey, root, commissionerKey, FabricId, CommissionerNodeId);
        var initiator = new CaseInitiator(root, epochIpk, FabricId, DeviceNodeId, commissionerNoc, commissionerKey, peerSessionId: 0xB2B2);

        // ----- Sigma1 → Sigma2 → Sigma3 → session -----
        var sigma1 = initiator.BuildSigma1();
        var sigma2 = device.OnSigma1(sigma1).Encode();
        var sigma3 = initiator.OnSigma2BuildSigma3(sigma2);
        var deviceSession = device.OnSigma3(sigma3);

        Assert.NotNull(deviceSession);
        Assert.NotNull(initiator.SessionKeys);

        // Both sides agree on every operational key.
        Assert.Equal(Convert.ToHexString(initiator.SessionKeys!.Value.I2R), Convert.ToHexString(deviceSession!.DecryptKey));
        Assert.Equal(Convert.ToHexString(initiator.SessionKeys.Value.R2I), Convert.ToHexString(deviceSession.EncryptKey));
        Assert.Equal(Convert.ToHexString(initiator.SessionKeys.Value.Attest), Convert.ToHexString(deviceSession.AttestationChallenge));

        // Identities propagated correctly.
        Assert.Equal(CommissionerNodeId, deviceSession.PeerNodeId);
        Assert.Equal((ushort)0xB2B2, deviceSession.PeerSessionId);
        Assert.True(initiator.DeviceNocVerified);
    }

    [Fact]
    public void Wrong_fabric_root_is_rejected_at_destination_id()
    {
        var rootKey = P256KeyPair.Generate();
        var root = OperationalCredentials.CreateRootCertificate(rootKey, RcacId);
        var epochIpk = RandomNumberGenerator.GetBytes(16);
        var deviceKey = P256KeyPair.Generate();
        var deviceNoc = OperationalCredentials.CreateNodeCertificate(rootKey, root, deviceKey, FabricId, DeviceNodeId);

        var fabrics = new FabricTable();
        fabrics.Add(index => new Fabric
        {
            FabricIndex = index, FabricId = FabricId, NodeId = DeviceNodeId,
            RootCertificate = root, Noc = deviceNoc, OperationalKey = deviceKey, EpochIpk = epochIpk,
        });
        var device = new CaseResponder(fabrics, 0x0001);

        // A commissioner on a DIFFERENT fabric (different root + IPK) — its destination id won't match.
        var rogueRootKey = P256KeyPair.Generate();
        var rogueRoot = OperationalCredentials.CreateRootCertificate(rogueRootKey, RcacId);
        var rogueKey = P256KeyPair.Generate();
        var rogueNoc = OperationalCredentials.CreateNodeCertificate(rogueRootKey, rogueRoot, rogueKey, FabricId, CommissionerNodeId);
        var rogue = new CaseInitiator(rogueRoot, RandomNumberGenerator.GetBytes(16), FabricId, DeviceNodeId, rogueNoc, rogueKey, 0x1);

        Assert.Throws<InvalidOperationException>(() => device.OnSigma1(rogue.BuildSigma1()));
    }
}

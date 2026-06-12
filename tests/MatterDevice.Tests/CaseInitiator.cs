using System.Security.Cryptography;
using MatterDevice.Commissioning.Case;
using MatterDevice.Core.Credentials;
using MatterDevice.Core.Crypto;

namespace MatterDevice.Tests;

/// <summary>
/// A minimal commissioner-side CASE driver (the initiator role), used by the tests to exercise the device
/// <see cref="CaseResponder"/>. A real controller plays this same role on the wire.
/// </summary>
internal sealed class CaseInitiator
{
    private readonly MatterCertificate _root;
    private readonly byte[] _operationalIpk;
    private readonly ulong _fabricId;
    private readonly ulong _deviceNodeId;
    private readonly byte[] _nocBytes;
    private readonly P256KeyPair _nocKey;
    private readonly ushort _peerSessionId;

    private readonly P256KeyPair _eph = P256KeyPair.Generate();
    private readonly byte[] _random = RandomNumberGenerator.GetBytes(32);
    private byte[] _sigma1Bytes = [];
    private byte[] _sharedSecret = [];

    public (byte[] I2R, byte[] R2I, byte[] Attest)? SessionKeys { get; private set; }
    public bool DeviceNocVerified { get; private set; }

    public CaseInitiator(MatterCertificate root, byte[] epochIpk, ulong fabricId, ulong deviceNodeId,
        MatterCertificate noc, P256KeyPair nocKey, ushort peerSessionId)
    {
        _root = root;
        var compressed = FabricCrypto.CompressedFabricId(root.EllipticCurvePublicKey, fabricId);
        _operationalIpk = FabricCrypto.OperationalIpk(epochIpk, compressed);
        _fabricId = fabricId;
        _deviceNodeId = deviceNodeId;
        _nocBytes = noc.Encode();
        _nocKey = nocKey;
        _peerSessionId = peerSessionId;
    }

    public byte[] BuildSigma1()
    {
        var destinationId = CaseCrypto.DestinationId(
            _operationalIpk, _random, _root.EllipticCurvePublicKey, _fabricId, _deviceNodeId);

        var sigma1 = new CaseMessages.Sigma1
        {
            InitiatorRandom = _random,
            InitiatorSessionId = _peerSessionId,
            DestinationId = destinationId,
            InitiatorEphPublicKey = _eph.PublicKey,
        };
        _sigma1Bytes = sigma1.Encode();
        return _sigma1Bytes;
    }

    public byte[] OnSigma2BuildSigma3(byte[] sigma2Bytes)
    {
        var sigma2 = CaseMessages.Sigma2.Decode(sigma2Bytes);
        _sharedSecret = _eph.EcdhSharedSecret(sigma2.ResponderEphPublicKey);

        // decrypt encrypted2, verify the device's NOC + signature
        var s2k = CaseCrypto.Sigma2Key(_sharedSecret, _operationalIpk, sigma2.ResponderRandom, sigma2.ResponderEphPublicKey, SHA256.HashData(_sigma1Bytes));
        var tbe2 = MatterAead.Decrypt(s2k, CaseCrypto.Sigma2Nonce, sigma2.Encrypted2, ReadOnlySpan<byte>.Empty);
        var data2 = CaseMessages.DecodeTbeData(tbe2);
        var deviceNoc = MatterCertificate.Decode(data2.Noc);

        var tbs2 = CaseMessages.EncodeTbsData(data2.Noc, data2.Icac, sigma2.ResponderEphPublicKey, _eph.PublicKey);
        DeviceNocVerified =
            OperationalCredentials.ValidateChain(deviceNoc, _root, _fabricId) &&
            P256.Verify(deviceNoc.EllipticCurvePublicKey, tbs2, data2.Signature);
        if (!DeviceNocVerified)
            throw new InvalidOperationException("Device NOC/signature did not verify.");

        // build Sigma3
        var tbs3 = CaseMessages.EncodeTbsData(_nocBytes, null, _eph.PublicKey, sigma2.ResponderEphPublicKey);
        var signature = _nocKey.Sign(tbs3);
        var tbe3 = CaseMessages.EncodeTbeData3(_nocBytes, null, signature);

        var th1And2 = SHA256.HashData(Concat(_sigma1Bytes, sigma2Bytes));
        var s3k = CaseCrypto.Sigma3Key(_sharedSecret, _operationalIpk, th1And2);
        var encrypted3 = MatterAead.Encrypt(s3k, CaseCrypto.Sigma3Nonce, tbe3, ReadOnlySpan<byte>.Empty);
        var sigma3 = new CaseMessages.Sigma3 { Encrypted3 = encrypted3 };
        var sigma3Bytes = sigma3.Encode();

        var thAll = SHA256.HashData(Concat(_sigma1Bytes, sigma2Bytes, sigma3Bytes));
        SessionKeys = CaseCrypto.SessionKeys(_sharedSecret, _operationalIpk, thAll);
        return sigma3Bytes;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var output = new byte[parts.Sum(p => p.Length)];
        var o = 0;
        foreach (var p in parts) { p.CopyTo(output, o); o += p.Length; }
        return output;
    }
}

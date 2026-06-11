using System.Security.Cryptography;
using MatterDevice.Core.Credentials;
using MatterDevice.Core.Crypto;
using MatterDevice.Core.Session;
using CoreOpCreds = MatterDevice.Core.Credentials.OperationalCredentials;

namespace MatterDevice.Commissioning.Case;

/// <summary>
/// The device (responder) side of a CASE handshake (Matter Core Spec §4.14.2), establishing an operational
/// secure session over an installed fabric. Drive it: <see cref="OnSigma1"/> → <see cref="OnSigma3"/>. The
/// SPAKE-style transcript/key-schedule is <see cref="CaseCrypto"/>; this class is the protocol plumbing —
/// fabric selection by destination id, ephemeral ECDH, NOC signatures, and the final session.
/// </summary>
public sealed class CaseResponder
{
    private readonly FabricTable _fabrics;
    private readonly ushort _localSessionId;

    private Fabric? _fabric;
    private byte[] _initiatorRandom = [];
    private byte[] _initiatorEphPub = [];
    private ushort _initiatorSessionId;
    private P256KeyPair _responderEph = null!;
    private byte[] _responderRandom = [];
    private byte[] _sharedSecret = [];
    private byte[] _sigma1Bytes = [];
    private byte[] _sigma2Bytes = [];

    public CaseResponder(FabricTable fabrics, ushort localSessionId)
    {
        _fabrics = fabrics;
        _localSessionId = localSessionId;
    }

    /// <summary>Step 1: consume Sigma1, select the fabric by destination id, return Sigma2.</summary>
    public CaseMessages.Sigma2 OnSigma1(ReadOnlySpan<byte> sigma1Tlv)
    {
        _sigma1Bytes = sigma1Tlv.ToArray();
        var sigma1 = CaseMessages.Sigma1.Decode(sigma1Tlv);
        _initiatorRandom = sigma1.InitiatorRandom;
        _initiatorEphPub = sigma1.InitiatorEphPublicKey;
        _initiatorSessionId = sigma1.InitiatorSessionId;

        _fabric = SelectFabric(sigma1.DestinationId, sigma1.InitiatorRandom)
                  ?? throw new InvalidOperationException("No fabric matches the Sigma1 destination id.");

        _responderEph = P256KeyPair.Generate();
        _responderRandom = RandomNumberGenerator.GetBytes(32);
        _sharedSecret = _responderEph.EcdhSharedSecret(_initiatorEphPub);

        var nocBytes = _fabric.Noc.Encode();
        var icacBytes = _fabric.Icac?.Encode();

        // TBSData2 signed with the responder (device) NOC private key.
        var tbs2 = CaseMessages.EncodeTbsData(nocBytes, icacBytes, _responderEph.PublicKey, _initiatorEphPub);
        var signature = _fabric.OperationalKey.Sign(tbs2);
        var resumptionId = RandomNumberGenerator.GetBytes(16);
        var tbe2 = CaseMessages.EncodeTbeData2(nocBytes, icacBytes, signature, resumptionId);

        var s2k = CaseCrypto.Sigma2Key(_sharedSecret, _fabric.OperationalIpk, _responderRandom, _responderEph.PublicKey);
        var encrypted2 = MatterAead.Encrypt(s2k, CaseCrypto.Sigma2Nonce, tbe2, ReadOnlySpan<byte>.Empty);

        var sigma2 = new CaseMessages.Sigma2
        {
            ResponderRandom = _responderRandom,
            ResponderSessionId = _localSessionId,
            ResponderEphPublicKey = _responderEph.PublicKey,
            Encrypted2 = encrypted2,
        };
        _sigma2Bytes = sigma2.Encode();
        return sigma2;
    }

    /// <summary>Step 2: consume Sigma3, validate the initiator's NOC + signature, return the operational session.</summary>
    public SecureSession? OnSigma3(ReadOnlySpan<byte> sigma3Tlv)
    {
        if (_fabric is null) throw new InvalidOperationException("Sigma3 before Sigma1.");
        var sigma3 = CaseMessages.Sigma3.Decode(sigma3Tlv);

        var th1And2 = SHA256.HashData(Concat(_sigma1Bytes, _sigma2Bytes));
        var s3k = CaseCrypto.Sigma3Key(_sharedSecret, _fabric.OperationalIpk, th1And2);

        byte[] tbe3;
        try
        {
            tbe3 = MatterAead.Decrypt(s3k, CaseCrypto.Sigma3Nonce, sigma3.Encrypted3, ReadOnlySpan<byte>.Empty);
        }
        catch (AeadAuthenticationException)
        {
            return null; // wrong key / tampered
        }

        var data3 = CaseMessages.DecodeTbeData(tbe3);
        var initiatorNoc = MatterCertificate.Decode(data3.Noc);

        // The initiator NOC must chain to our fabric root.
        if (!CoreOpCreds.ValidateChain(initiatorNoc, _fabric.RootCertificate, _fabric.FabricId))
            return null;

        // Verify the initiator's signature over TBSData3 (sender = initiator).
        var tbs3 = CaseMessages.EncodeTbsData(data3.Noc, data3.Icac, _initiatorEphPub, _responderEph.PublicKey);
        if (!P256.Verify(initiatorNoc.EllipticCurvePublicKey, tbs3, data3.Signature))
            return null;

        // Final session keys.
        var thAll = SHA256.HashData(Concat(_sigma1Bytes, _sigma2Bytes, sigma3Tlv.ToArray()));
        var (i2r, r2i, attest) = CaseCrypto.SessionKeys(_sharedSecret, _fabric.OperationalIpk, thAll);

        return new SecureSession
        {
            LocalSessionId = _localSessionId,
            PeerSessionId = _initiatorSessionId,
            PeerNodeId = initiatorNoc.Subject.NodeId ?? 0,
            LocalNodeId = _fabric.NodeId,
            Origin = SessionOrigin.Case,
            DecryptKey = i2r,  // device decrypts inbound with I2R
            EncryptKey = r2i,  // device encrypts outbound with R2I
            AttestationChallenge = attest,
        };
    }

    private Fabric? SelectFabric(byte[] destinationId, byte[] initiatorRandom)
    {
        foreach (var fabric in _fabrics.All)
        {
            var candidate = CaseCrypto.DestinationId(
                fabric.OperationalIpk, initiatorRandom, fabric.RootPublicKey, fabric.FabricId, fabric.NodeId);
            if (CryptographicOperations.FixedTimeEquals(candidate, destinationId))
                return fabric;
        }
        return null;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var output = new byte[parts.Sum(p => p.Length)];
        var o = 0;
        foreach (var p in parts) { p.CopyTo(output, o); o += p.Length; }
        return output;
    }
}

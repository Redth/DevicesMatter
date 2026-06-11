using System.Security.Cryptography;
using MatterDevice.Core.Crypto;

namespace MatterDevice.Core.Credentials;

/// <summary>
/// Generates and validates Matter operational certificates (RCAC / NOC). Certificate signatures are
/// computed over the to-be-signed TLV bytes with the issuer's key; this is internally consistent and
/// exercises the full chain-validation path. (Byte-level chip-tool interop additionally pins the signature
/// to the X.509 DER TBSCertificate — a mechanical conversion tracked in the milestone doc.)
/// </summary>
public static class OperationalCredentials
{
    /// <summary>Seconds between the Unix epoch and the Matter epoch (2000-01-01T00:00:00Z).</summary>
    public const long MatterEpochUnixOffset = 946684800;

    /// <summary>Builds a self-signed Root CA certificate (RCAC) for a fabric.</summary>
    public static MatterCertificate CreateRootCertificate(P256KeyPair rootKey, ulong rcacId, string commonName = "Matter Dev Root")
    {
        var dn = new MatterDistinguishedName()
            .AddCommonName(commonName)
            .AddMatterId(DnAttributeType.MatterRcacId, rcacId);
        var skid = SubjectKeyId(rootKey.PublicKey);

        var cert = new MatterCertificate
        {
            SerialNumber = RandomNumberGenerator.GetBytes(8),
            Issuer = dn, // self-signed: issuer == subject
            Subject = dn,
            NotBefore = 0,
            NotAfter = 0, // no well-defined expiry
            EllipticCurvePublicKey = rootKey.PublicKey,
            Extensions = new CertificateExtensions
            {
                IsCa = true,
                KeyUsage = (ushort)(MatterKeyUsage.KeyCertSign | MatterKeyUsage.CrlSign),
                SubjectKeyId = skid,
                AuthorityKeyId = skid, // self-signed
            },
        };
        Sign(cert, rootKey);
        return cert;
    }

    /// <summary>Builds a Node Operational Certificate (NOC) signed by the root, for a node on a fabric.</summary>
    public static MatterCertificate CreateNodeCertificate(
        P256KeyPair issuerKey, MatterCertificate issuerCert, P256KeyPair nodeKey, ulong fabricId, ulong nodeId)
    {
        var subject = new MatterDistinguishedName()
            .AddMatterId(DnAttributeType.MatterNodeId, nodeId)
            .AddMatterId(DnAttributeType.MatterFabricId, fabricId);

        var cert = new MatterCertificate
        {
            SerialNumber = RandomNumberGenerator.GetBytes(8),
            Issuer = issuerCert.Subject,
            Subject = subject,
            NotBefore = 0,
            NotAfter = 0,
            EllipticCurvePublicKey = nodeKey.PublicKey,
            Extensions = new CertificateExtensions
            {
                IsCa = false,
                KeyUsage = (ushort)MatterKeyUsage.DigitalSignature,
                SubjectKeyId = SubjectKeyId(nodeKey.PublicKey),
                AuthorityKeyId = issuerCert.Extensions.SubjectKeyId,
            },
        };
        Sign(cert, issuerKey);
        return cert;
    }

    /// <summary>Signs a certificate's to-be-signed bytes with the issuer key, populating <see cref="MatterCertificate.Signature"/>.</summary>
    public static void Sign(MatterCertificate cert, P256KeyPair issuerKey) =>
        cert.Signature = issuerKey.Sign(cert.EncodeToBeSigned());

    /// <summary>Verifies a certificate's signature against an issuer public key (over the TBS TLV bytes).</summary>
    public static bool VerifySignature(MatterCertificate cert, ReadOnlySpan<byte> issuerPublicKey) =>
        P256.Verify(issuerPublicKey, cert.EncodeToBeSigned(), cert.Signature);

    /// <summary>
    /// Validates that <paramref name="noc"/> chains to <paramref name="root"/> on the expected fabric:
    /// the NOC is signed by the root (no ICAC case), the root is self-consistent, and the NOC carries the
    /// expected fabric id.
    /// </summary>
    public static bool ValidateChain(MatterCertificate noc, MatterCertificate root, ulong expectedFabricId)
    {
        if (noc.Subject.FabricId != expectedFabricId)
            return false;
        if (!VerifySignature(noc, root.EllipticCurvePublicKey))
            return false;
        if (!VerifySignature(root, root.EllipticCurvePublicKey)) // self-signed root
            return false;
        return true;
    }

    /// <summary>X.509-style SubjectKeyIdentifier: the 20-byte SHA-1 of the public key point.</summary>
    public static byte[] SubjectKeyId(ReadOnlySpan<byte> publicKey) => SHA1.HashData(publicKey);
}

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MatterDevice.Core.Crypto;

/// <summary>
/// A NIST P-256 (secp256r1) key pair used for Matter operational crypto — CASE ephemeral ECDH and ECDSA
/// signatures over NOC/DAC keys. Public keys are 65-byte uncompressed points (<c>0x04 ‖ X ‖ Y</c>),
/// private keys are the 32-byte scalar, and signatures are the raw 64-byte <c>r ‖ s</c> form Matter uses.
/// </summary>
public sealed class P256KeyPair
{
    /// <summary>The 32-byte private scalar (D).</summary>
    public byte[] PrivateKey { get; }

    /// <summary>The 65-byte uncompressed public point (0x04 ‖ X ‖ Y).</summary>
    public byte[] PublicKey { get; }

    private P256KeyPair(byte[] privateKey, byte[] publicKey)
    {
        PrivateKey = privateKey;
        PublicKey = publicKey;
    }

    /// <summary>Generates a fresh random key pair.</summary>
    public static P256KeyPair Generate()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = ec.ExportParameters(includePrivateParameters: true);
        return new P256KeyPair(LeftPad(p.D!, 32), Uncompressed(p.Q));
    }

    /// <summary>Reconstructs a key pair from its 32-byte private scalar.</summary>
    public static P256KeyPair FromPrivateKey(ReadOnlySpan<byte> d)
    {
        var dArr = LeftPad(d.ToArray(), 32);
        using var ec = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, D = dArr });
        var p = ec.ExportParameters(false);
        return new P256KeyPair(dArr, Uncompressed(p.Q));
    }

    /// <summary>
    /// The raw ECDH shared secret with a peer's public key — the 32-byte X coordinate of
    /// <c>privateKey · peerPublic</c> (Matter uses this directly as HKDF input keying material).
    /// </summary>
    public byte[] EcdhSharedSecret(ReadOnlySpan<byte> peerPublicKey)
    {
        using var self = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = PrivateKey,
            Q = PointFromUncompressed(PublicKey),
        });
        using var peer = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = PointFromUncompressed(peerPublicKey),
        });
        return self.DeriveRawSecretAgreement(peer.PublicKey);
    }

    /// <summary>Signs <paramref name="message"/> (SHA-256 + ECDSA), returning the raw 64-byte r‖s signature.</summary>
    public byte[] Sign(ReadOnlySpan<byte> message)
    {
        using var ec = CreateEcDsa();
        return ec.SignData(message.ToArray(), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>A DER-encoded PKCS#10 CertificationRequest for this key (the device's operational CSR).</summary>
    public byte[] CreateCsr()
    {
        using var ec = CreateEcDsa();
        var request = new CertificateRequest("CN=Matter Operational", ec, HashAlgorithmName.SHA256);
        return request.CreateSigningRequest();
    }

    /// <summary>Extracts the 65-byte uncompressed public key from a DER-encoded PKCS#10 CSR.</summary>
    public static byte[] PublicKeyFromCsr(byte[] csrDer)
    {
        var request = CertificateRequest.LoadSigningRequest(
            csrDer, HashAlgorithmName.SHA256, signerSignaturePadding: System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        using var ec = request.PublicKey.GetECDsaPublicKey()
                       ?? throw new InvalidOperationException("CSR does not carry an EC public key.");
        var p = ec.ExportParameters(false);
        var output = new byte[65];
        output[0] = 0x04;
        LeftPad(p.Q.X!, 32).CopyTo(output, 1);
        LeftPad(p.Q.Y!, 32).CopyTo(output, 33);
        return output;
    }

    private ECDsa CreateEcDsa() => ECDsa.Create(new ECParameters
    {
        Curve = ECCurve.NamedCurves.nistP256,
        D = PrivateKey,
        Q = PointFromUncompressed(PublicKey),
    });

    private static byte[] Uncompressed(ECPoint q)
    {
        var output = new byte[65];
        output[0] = 0x04;
        LeftPad(q.X!, 32).CopyTo(output, 1);
        LeftPad(q.Y!, 32).CopyTo(output, 33);
        return output;
    }

    internal static ECPoint PointFromUncompressed(ReadOnlySpan<byte> point)
    {
        if (point.Length != 65 || point[0] != 0x04)
            throw new ArgumentException("Expected a 65-byte uncompressed P-256 point.", nameof(point));
        return new ECPoint { X = point.Slice(1, 32).ToArray(), Y = point.Slice(33, 32).ToArray() };
    }

    private static byte[] LeftPad(byte[] value, int length)
    {
        if (value.Length == length) return value;
        if (value.Length > length) return value[^length..];
        var padded = new byte[length];
        value.CopyTo(padded, length - value.Length);
        return padded;
    }
}

/// <summary>P-256 signature verification (raw 64-byte r‖s over a SHA-256 digest).</summary>
public static class P256
{
    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        using var ec = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = P256KeyPair.PointFromUncompressed(publicKey),
        });
        return ec.VerifyData(message.ToArray(), signature.ToArray(), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }
}

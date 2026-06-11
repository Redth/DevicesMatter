using MatterDevice.Core.Crypto;

namespace MatterDevice.Commissioning.OperationalCredentials;

/// <summary>
/// Holds a device's attestation credentials — the Device Attestation Certificate (DAC) key pair, the DAC
/// and PAI certificates (X.509 DER), and the Certification Declaration (CD) blob — and signs the
/// attestation / CSR responses with the DAC key (Matter Core Spec §6.2, §11.17).
/// </summary>
/// <remarks>
/// For development, load the CHIP <c>credentials/test</c> DAC/PAI/CD set (test Vendor ID 0xFFF1). The
/// signing logic is production-shaped; only the certificate material changes for a certified product.
/// </remarks>
public sealed class DeviceAttestationProvider(P256KeyPair dacKey, byte[] dacCertificateDer, byte[] paiCertificateDer, byte[] certificationDeclaration)
{
    public P256KeyPair DacKey { get; } = dacKey;
    public byte[] DacCertificateDer { get; } = dacCertificateDer;
    public byte[] PaiCertificateDer { get; } = paiCertificateDer;
    public byte[] CertificationDeclaration { get; } = certificationDeclaration;

    /// <summary>
    /// Signs an attestation/CSR elements buffer with the DAC key over <c>elements ‖ attestationChallenge</c>
    /// (the message-to-be-signed for both AttestationResponse and CSRResponse), returning the raw 64-byte signature.
    /// </summary>
    public byte[] SignWithDac(ReadOnlySpan<byte> elements, ReadOnlySpan<byte> attestationChallenge)
    {
        var tbs = new byte[elements.Length + attestationChallenge.Length];
        elements.CopyTo(tbs);
        attestationChallenge.CopyTo(tbs.AsSpan(elements.Length));
        return DacKey.Sign(tbs);
    }

    /// <summary>Verifies a DAC-signed elements buffer (commissioner-side check / tests).</summary>
    public static bool VerifyDacSignature(ReadOnlySpan<byte> dacPublicKey, ReadOnlySpan<byte> elements, ReadOnlySpan<byte> attestationChallenge, ReadOnlySpan<byte> signature)
    {
        var tbs = new byte[elements.Length + attestationChallenge.Length];
        elements.CopyTo(tbs);
        attestationChallenge.CopyTo(tbs.AsSpan(elements.Length));
        return P256.Verify(dacPublicKey, tbs, signature);
    }
}

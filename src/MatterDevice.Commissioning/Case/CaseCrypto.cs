using System.Buffers.Binary;
using System.Security.Cryptography;

namespace MatterDevice.Commissioning.Case;

/// <summary>
/// CASE key-schedule primitives (Matter Core Spec §4.14.2): the destination id and the S2K / S3K / SEK
/// HKDF derivations, plus the fixed AEAD nonce constants. All constants verified against
/// connectedhomeip <c>CASESession.cpp</c> / <c>CASEDestinationId.cpp</c>.
/// </summary>
public static class CaseCrypto
{
    // Fixed 13-byte AEAD nonces for encrypted2 / encrypted3.
    public static readonly byte[] Sigma2Nonce = "NCASE_Sigma2N"u8.ToArray();
    public static readonly byte[] Sigma3Nonce = "NCASE_Sigma3N"u8.ToArray();

    /// <summary>
    /// destinationId = HMAC-SHA256(key = operationalIpk,
    /// message = initiatorRandom ‖ rootPublicKey(65) ‖ fabricId(LE 8) ‖ nodeId(LE 8)).
    /// (fabricId/nodeId are little-endian here — distinct from the compressed-fabric-id big-endian.)
    /// </summary>
    public static byte[] DestinationId(
        ReadOnlySpan<byte> operationalIpk, ReadOnlySpan<byte> initiatorRandom,
        ReadOnlySpan<byte> rootPublicKey65, ulong fabricId, ulong nodeId)
    {
        var msg = new byte[initiatorRandom.Length + rootPublicKey65.Length + 8 + 8];
        var o = 0;
        initiatorRandom.CopyTo(msg.AsSpan(o)); o += initiatorRandom.Length;
        rootPublicKey65.CopyTo(msg.AsSpan(o)); o += rootPublicKey65.Length;
        BinaryPrimitives.WriteUInt64LittleEndian(msg.AsSpan(o), fabricId); o += 8;
        BinaryPrimitives.WriteUInt64LittleEndian(msg.AsSpan(o), nodeId);
        return HMACSHA256.HashData(operationalIpk, msg);
    }

    /// <summary>
    /// S2K = HKDF-SHA256(IKM = sharedSecret,
    /// salt = IPK ‖ responderRandom ‖ responderEphPubKey ‖ SHA256(Sigma1 bytes), info = "Sigma2", 16).
    /// (The Sigma1 transcript hash IS part of the S2K salt — verified against matter.js CaseClient.)
    /// </summary>
    public static byte[] Sigma2Key(ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> ipk,
        ReadOnlySpan<byte> responderRandom, ReadOnlySpan<byte> responderEphPublicKey, ReadOnlySpan<byte> sigma1Hash)
    {
        var salt = new byte[ipk.Length + responderRandom.Length + responderEphPublicKey.Length + sigma1Hash.Length];
        var o = 0;
        ipk.CopyTo(salt.AsSpan(o)); o += ipk.Length;
        responderRandom.CopyTo(salt.AsSpan(o)); o += responderRandom.Length;
        responderEphPublicKey.CopyTo(salt.AsSpan(o)); o += responderEphPublicKey.Length;
        sigma1Hash.CopyTo(salt.AsSpan(o));
        return Hkdf16(sharedSecret, salt, "Sigma2"u8);
    }

    /// <summary>S3K = HKDF-SHA256(IKM = sharedSecret, salt = IPK ‖ SHA256(Sigma1 ‖ Sigma2), info = "Sigma3", 16).</summary>
    public static byte[] Sigma3Key(ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> ipk, ReadOnlySpan<byte> transcriptHash1And2)
    {
        var salt = Concat(ipk, transcriptHash1And2, default);
        return Hkdf16(sharedSecret, salt, "Sigma3"u8);
    }

    /// <summary>
    /// SEK = HKDF-SHA256(IKM = sharedSecret, salt = IPK ‖ SHA256(Sigma1 ‖ Sigma2 ‖ Sigma3),
    /// info = "SessionKeys", 48) split into I2R ‖ R2I ‖ AttestationChallenge.
    /// </summary>
    public static (byte[] I2R, byte[] R2I, byte[] AttestationChallenge) SessionKeys(
        ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> ipk, ReadOnlySpan<byte> transcriptHashAll)
    {
        var salt = Concat(ipk, transcriptHashAll, default);
        Span<byte> keys = stackalloc byte[48];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, keys, salt, "SessionKeys"u8);
        return (keys[..16].ToArray(), keys[16..32].ToArray(), keys[32..48].ToArray());
    }

    private static byte[] Hkdf16(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info)
    {
        Span<byte> output = stackalloc byte[16];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, output, salt, info);
        return output.ToArray();
    }

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c)
    {
        var output = new byte[a.Length + b.Length + c.Length];
        a.CopyTo(output);
        b.CopyTo(output.AsSpan(a.Length));
        c.CopyTo(output.AsSpan(a.Length + b.Length));
        return output;
    }
}

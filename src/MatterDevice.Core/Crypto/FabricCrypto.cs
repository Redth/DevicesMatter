using System.Buffers.Binary;
using System.Security.Cryptography;

namespace MatterDevice.Core.Crypto;

/// <summary>
/// Fabric-level key derivations (Matter Core Spec §4.3.2.2, §4.15.x): the Compressed Fabric Identifier
/// and the Operational Identity Protection Key (IPK) that CASE folds into its salts and destination id.
/// </summary>
public static class FabricCrypto
{
    /// <summary>
    /// The 8-byte Compressed Fabric Identifier:
    /// <c>HKDF-SHA256(IKM = rootPublicKey[1..] (64B, 0x04 prefix dropped), salt = fabricId (8B big-endian),
    /// info = "CompressedFabric", L = 8)</c>. (Input/salt roles verified against
    /// connectedhomeip <c>GenerateCompressedFabricId</c>.)
    /// </summary>
    public static byte[] CompressedFabricId(ReadOnlySpan<byte> rootPublicKey65, ulong fabricId)
    {
        if (rootPublicKey65.Length != 65 || rootPublicKey65[0] != 0x04)
            throw new ArgumentException("Root public key must be a 65-byte uncompressed point.", nameof(rootPublicKey65));

        var ikm = rootPublicKey65[1..]; // 64 bytes, X‖Y without the 0x04 prefix
        Span<byte> salt = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(salt, fabricId);

        Span<byte> output = stackalloc byte[8];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, output, salt, "CompressedFabric"u8);
        return output.ToArray();
    }

    /// <summary>
    /// The 16-byte Operational IPK:
    /// <c>HKDF-SHA256(IKM = epochKey (16B), salt = compressedFabricId (8B), info = "GroupKey v1.0", L = 16)</c>.
    /// The value fed to CASE's destination id and S2K/S3K/SEK salts — derived from the raw IPK delivered in AddNOC.
    /// </summary>
    public static byte[] OperationalIpk(ReadOnlySpan<byte> epochKey16, ReadOnlySpan<byte> compressedFabricId8)
    {
        if (epochKey16.Length != 16)
            throw new ArgumentException("Epoch key (IPKValue) must be 16 bytes.", nameof(epochKey16));

        Span<byte> output = stackalloc byte[16];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, epochKey16, output, compressedFabricId8, "GroupKey v1.0"u8);
        return output.ToArray();
    }
}

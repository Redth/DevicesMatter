using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace MatterDevice.Core.Crypto;

/// <summary>Raised when an AEAD authentication tag fails to verify (tampering, wrong key, or wrong nonce).</summary>
public sealed class AeadAuthenticationException(string message) : CryptographicException(message);

/// <summary>
/// Matter message-layer AEAD (Matter Core Spec §4.7): AES-128-CCM with a 13-byte nonce and a 16-byte
/// integrity tag (MIC). The session keys come from PASE/CASE; the nonce is built by the message layer
/// (<c>securityFlags ‖ counter ‖ sourceNodeId</c>) and the AAD is the unencrypted message header.
/// </summary>
/// <remarks>
/// Uses the BCL <see cref="AesCcm"/> when the platform supports it (Linux/Windows — the IoT deployment
/// targets), and falls back to BouncyCastle's pure-managed CCM otherwise (notably macOS, where the BCL's
/// AES-CCM is unavailable). Both produce identical bytes; only the implementation differs.
/// </remarks>
public static class MatterAead
{
    public const int TagLength = 16;   // 128-bit MIC
    public const int NonceLength = 13;
    public const int KeyLength = 16;   // AES-128

    /// <summary>Encrypts <paramref name="plaintext"/>, returning ciphertext ‖ 16-byte tag.</summary>
    public static byte[] Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        ValidateKey(key);
        return AesCcm.IsSupported
            ? EncryptBcl(key, nonce, plaintext, aad)
            : EncryptBouncyCastle(key, nonce, plaintext, aad);
    }

    /// <summary>
    /// Decrypts <paramref name="ciphertextAndTag"/> (ciphertext ‖ 16-byte tag), verifying the tag against
    /// <paramref name="aad"/>. Throws <see cref="AeadAuthenticationException"/> if authentication fails.
    /// </summary>
    public static byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertextAndTag, ReadOnlySpan<byte> aad)
    {
        ValidateKey(key);
        if (ciphertextAndTag.Length < TagLength)
            throw new ArgumentException("Ciphertext is shorter than the authentication tag.", nameof(ciphertextAndTag));
        return AesCcm.IsSupported
            ? DecryptBcl(key, nonce, ciphertextAndTag, aad)
            : DecryptBouncyCastle(key, nonce, ciphertextAndTag, aad);
    }

    // ---- BCL path (Linux/Windows) ---------------------------------------

    private static byte[] EncryptBcl(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagLength];
        using var ccm = new AesCcm(key);
        ccm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        return Concat(ciphertext, tag);
    }

    private static byte[] DecryptBcl(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertextAndTag, ReadOnlySpan<byte> aad)
    {
        var ctLen = ciphertextAndTag.Length - TagLength;
        var plaintext = new byte[ctLen];
        using var ccm = new AesCcm(key);
        try
        {
            ccm.Decrypt(nonce, ciphertextAndTag[..ctLen], ciphertextAndTag[ctLen..], plaintext, aad);
        }
        catch (AuthenticationTagMismatchException ex)
        {
            throw new AeadAuthenticationException(ex.Message);
        }
        return plaintext;
    }

    // ---- BouncyCastle path (macOS / anywhere) ---------------------------

    private static byte[] EncryptBouncyCastle(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        var cipher = NewCcm(true, key, nonce, aad);
        var input = plaintext.ToArray();
        var output = new byte[cipher.GetOutputSize(input.Length)]; // ciphertext + tag
        var n = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        cipher.DoFinal(output, n);
        return output;
    }

    private static byte[] DecryptBouncyCastle(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertextAndTag, ReadOnlySpan<byte> aad)
    {
        var cipher = NewCcm(false, key, nonce, aad);
        var input = ciphertextAndTag.ToArray();
        var output = new byte[cipher.GetOutputSize(input.Length)]; // plaintext
        try
        {
            var n = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            cipher.DoFinal(output, n);
        }
        catch (InvalidCipherTextException ex)
        {
            throw new AeadAuthenticationException(ex.Message);
        }
        return output;
    }

    private static CcmBlockCipher NewCcm(bool forEncryption, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad)
    {
        var cipher = new CcmBlockCipher(new AesEngine());
        cipher.Init(forEncryption, new AeadParameters(new KeyParameter(key.ToArray()), TagLength * 8, nonce.ToArray(), aad.ToArray()));
        return cipher;
    }

    // ---- helpers ---------------------------------------------------------

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var output = new byte[a.Length + b.Length];
        a.CopyTo(output);
        b.CopyTo(output.AsSpan(a.Length));
        return output;
    }

    private static void ValidateKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeyLength)
            throw new ArgumentException($"Matter session keys are {KeyLength} bytes (AES-128).", nameof(key));
    }
}

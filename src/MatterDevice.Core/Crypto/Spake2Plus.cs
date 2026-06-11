using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using BigInteger = Org.BouncyCastle.Math.BigInteger;
using EcPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace MatterDevice.Core.Crypto;

/// <summary>
/// SPAKE2+ over NIST P-256, in the Matter convention (the <c>draft-bar-cfrg-spake2plus-01</c> transcript
/// that Matter — not RFC 9383 final — uses). This is the cryptographic heart of PASE.
/// </summary>
/// <remarks>
/// <para>
/// All public points are 65-byte uncompressed encodings (<c>0x04 || X || Y</c>) and all scalars are
/// 32-byte big-endian. EC point arithmetic (point add, scalar-multiply an arbitrary point, decompress)
/// is not exposed by the .NET BCL, so BouncyCastle supplies the curve math; PBKDF2/HKDF/HMAC/SHA come
/// from <see cref="System.Security.Cryptography"/>.
/// </para>
/// <para>
/// Roles: the commissioner is the prover and sends <c>X = x·P + w0·M</c>; the device is the verifier and
/// sends <c>Y = y·P + w0·N</c>. The shared secret is <c>Z = y·(X − w0·M)</c> and <c>V = y·L</c> where
/// <c>L = w1·P</c>. <c>Ka‖Ke = SHA-256(TT)</c>, then confirmation keys derive from <c>Ka</c>.
/// </para>
/// </remarks>
public sealed class Spake2Plus
{
    // SPAKE2+ seed points for P-256 (draft-bar-cfrg-spake2plus-01 / RFC 9383), compressed form.
    private const string MCompressedHex = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
    private const string NCompressedHex = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";

    private static readonly X9ECParameters Curve = ECNamedCurveTable.GetByName("P-256")!;
    private static readonly ECDomainParameters Domain =
        new(Curve.Curve, Curve.G, Curve.N, Curve.H, Curve.GetSeed());

    private readonly EcPoint _m;
    private readonly EcPoint _n;

    public Spake2Plus()
    {
        _m = DecodePoint(Convert.FromHexString(MCompressedHex));
        _n = DecodePoint(Convert.FromHexString(NCompressedHex));
    }

    /// <summary>The order n of the P-256 group.</summary>
    public static BigInteger Order => Curve.N;

    /// <summary>The M seed point, 65-byte uncompressed (as it appears in the transcript).</summary>
    public byte[] MUncompressed => _m.GetEncoded(false);

    /// <summary>The N seed point, 65-byte uncompressed (as it appears in the transcript).</summary>
    public byte[] NUncompressed => _n.GetEncoded(false);

    // ---- w0 / w1 from the passcode --------------------------------------

    /// <summary>
    /// Derives the SPAKE2+ scalars <c>w0</c> and <c>w1</c> from the setup passcode:
    /// <c>PBKDF2-HMAC-SHA256(passcode_le32, salt, iterations, 80)</c> split into two 40-byte halves, each
    /// interpreted big-endian and reduced mod n. Returns both as 32-byte big-endian scalars.
    /// </summary>
    public static (byte[] W0, byte[] W1) ComputeW0W1(uint passcode, ReadOnlySpan<byte> salt, int iterations)
    {
        Span<byte> pin = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(pin, passcode);

        var ws = Rfc2898DeriveBytes.Pbkdf2(pin, salt, iterations, HashAlgorithmName.SHA256, 80);
        var w0 = new BigInteger(1, ws, 0, 40).Mod(Curve.N);
        var w1 = new BigInteger(1, ws, 40, 40).Mod(Curve.N);
        return (To32(w0), To32(w1));
    }

    /// <summary>A uniformly random SPAKE2+ scalar in [1, n−1], as a 32-byte big-endian value.</summary>
    public static byte[] RandomScalar()
    {
        while (true)
        {
            var candidate = new byte[32];
            RandomNumberGenerator.Fill(candidate);
            var s = new BigInteger(1, candidate).Mod(Curve.N);
            if (s.SignValue != 0)
                return To32(s);
        }
    }

    /// <summary>The verifier point <c>L = w1·P</c> (65-byte uncompressed), what a device stores instead of w1.</summary>
    public byte[] ComputeL(ReadOnlySpan<byte> w1) =>
        Curve.G.Multiply(ToScalar(w1)).Normalize().GetEncoded(false);

    // ---- shares ----------------------------------------------------------

    /// <summary>Verifier (device) public share <c>Y = y·P + w0·N</c> (65-byte uncompressed).</summary>
    public byte[] ComputeY(ReadOnlySpan<byte> y, ReadOnlySpan<byte> w0)
    {
        var point = Curve.G.Multiply(ToScalar(y)).Add(_n.Multiply(ToScalar(w0)));
        return point.Normalize().GetEncoded(false);
    }

    /// <summary>Prover (commissioner) public share <c>X = x·P + w0·M</c> — used by tests / a controller harness.</summary>
    public byte[] ComputeX(ReadOnlySpan<byte> x, ReadOnlySpan<byte> w0)
    {
        var point = Curve.G.Multiply(ToScalar(x)).Add(_m.Multiply(ToScalar(w0)));
        return point.Normalize().GetEncoded(false);
    }

    /// <summary>
    /// Verifier shared values from the prover's share X: <c>Z = y·(X − w0·M)</c> and <c>V = y·L</c>.
    /// Throws if X is not a valid point on the curve. Both returned as 65-byte uncompressed points.
    /// </summary>
    public (byte[] Z, byte[] V) ComputeVerifierZV(ReadOnlySpan<byte> y, ReadOnlySpan<byte> x65, ReadOnlySpan<byte> w0, ReadOnlySpan<byte> l65)
    {
        var yScalar = ToScalar(y);
        var bigX = DecodePoint(x65.ToArray());
        var bigL = DecodePoint(l65.ToArray());

        var w0M = _m.Multiply(ToScalar(w0));
        var z = bigX.Subtract(w0M).Multiply(yScalar).Normalize().GetEncoded(false);
        var v = bigL.Multiply(yScalar).Normalize().GetEncoded(false);
        return (z, v);
    }

    /// <summary>
    /// Prover (commissioner) shared values from the verifier's share Y: <c>Z = x·(Y − w0·N)</c> and
    /// <c>V = w1·(Y − w0·N)</c>. Provided for a controller / test harness (the mirror of
    /// <see cref="ComputeVerifierZV"/>). Both returned as 65-byte uncompressed points.
    /// </summary>
    public (byte[] Z, byte[] V) ComputeProverZV(ReadOnlySpan<byte> x, ReadOnlySpan<byte> w1, ReadOnlySpan<byte> y65, ReadOnlySpan<byte> w0)
    {
        var bigY = DecodePoint(y65.ToArray());
        var yMinusW0N = bigY.Subtract(_n.Multiply(ToScalar(w0)));
        var z = yMinusW0N.Multiply(ToScalar(x)).Normalize().GetEncoded(false);
        var v = yMinusW0N.Multiply(ToScalar(w1)).Normalize().GetEncoded(false);
        return (z, v);
    }

    // ---- transcript + key schedule --------------------------------------

    /// <summary>
    /// Builds the SPAKE2+ transcript TT. Each element is length-prefixed with an 8-byte little-endian
    /// uint64. Order: Context, prover identity, verifier identity, M, N, X, Y, Z, V, w0. In Matter both
    /// identities are empty (each contributing only its 8-byte zero length prefix) — see
    /// <see cref="BuildMatterTranscript"/>; the generic overload exists so the implementation can be
    /// validated against the RFC 9383 / draft-01 test vectors, which use non-empty identities.
    /// </summary>
    public static byte[] BuildTranscript(
        ReadOnlySpan<byte> context, ReadOnlySpan<byte> proverIdentity, ReadOnlySpan<byte> verifierIdentity,
        ReadOnlySpan<byte> m, ReadOnlySpan<byte> n,
        ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, ReadOnlySpan<byte> z, ReadOnlySpan<byte> v,
        ReadOnlySpan<byte> w0)
    {
        using var ms = new MemoryStream();
        void Add(ReadOnlySpan<byte> bytes)
        {
            Span<byte> len = stackalloc byte[8];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(len, (ulong)bytes.Length);
            ms.Write(len);
            ms.Write(bytes);
        }
        Add(context);
        Add(proverIdentity);
        Add(verifierIdentity);
        Add(m);
        Add(n);
        Add(x);
        Add(y);
        Add(z);
        Add(v);
        Add(w0);
        return ms.ToArray();
    }

    /// <summary>The Matter transcript: <see cref="BuildTranscript"/> with both identities empty.</summary>
    public static byte[] BuildMatterTranscript(
        ReadOnlySpan<byte> context, ReadOnlySpan<byte> m, ReadOnlySpan<byte> n,
        ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, ReadOnlySpan<byte> z, ReadOnlySpan<byte> v,
        ReadOnlySpan<byte> w0) =>
        BuildTranscript(context, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, m, n, x, y, z, v, w0);

    /// <summary><c>Ka = SHA-256(TT)[0..16)</c>, <c>Ke = SHA-256(TT)[16..32)</c>.</summary>
    public static (byte[] Ka, byte[] Ke) DeriveKaKe(ReadOnlySpan<byte> transcript)
    {
        var hash = SHA256.HashData(transcript);
        return (hash[..16], hash[16..32]);
    }

    /// <summary><c>KcA‖KcB = HKDF-SHA256(Ka, salt=∅, info="ConfirmationKeys", 32)</c>.</summary>
    public static (byte[] KcA, byte[] KcB) DeriveConfirmationKeys(ReadOnlySpan<byte> ka)
    {
        Span<byte> kc = stackalloc byte[32];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ka, kc,
            salt: ReadOnlySpan<byte>.Empty, info: "ConfirmationKeys"u8);
        return (kc[..16].ToArray(), kc[16..32].ToArray());
    }

    /// <summary>A SPAKE2+ confirmation MAC: <c>HMAC-SHA256(key, peerShare)</c>.</summary>
    public static byte[] ConfirmationMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> peerShare) =>
        HMACSHA256.HashData(key, peerShare);

    /// <summary>
    /// The post-PASE session keys: <c>HKDF-SHA256(Ke, salt=∅, info="SessionKeys", 48)</c> split into
    /// three 16-byte keys — Initiator→Responder, Responder→Initiator, and the Attestation Challenge.
    /// The device decrypts inbound with I2R and encrypts outbound with R2I.
    /// </summary>
    public static (byte[] I2R, byte[] R2I, byte[] AttestationChallenge) DeriveSessionKeys(ReadOnlySpan<byte> ke)
    {
        Span<byte> keys = stackalloc byte[48];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ke, keys,
            salt: ReadOnlySpan<byte>.Empty, info: "SessionKeys"u8);
        return (keys[..16].ToArray(), keys[16..32].ToArray(), keys[32..48].ToArray());
    }

    // ---- helpers ---------------------------------------------------------

    private static EcPoint DecodePoint(byte[] encoded) => Domain.Curve.DecodePoint(encoded);
    private static BigInteger ToScalar(ReadOnlySpan<byte> be32) => new(1, be32.ToArray());

    private static byte[] To32(BigInteger value)
    {
        var bytes = value.ToByteArrayUnsigned();
        if (bytes.Length == 32)
            return bytes;
        var padded = new byte[32];
        Array.Copy(bytes, 0, padded, 32 - bytes.Length, bytes.Length);
        return padded;
    }
}

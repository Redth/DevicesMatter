using System.Security.Cryptography;
using System.Text;
using MatterDevice.Core.Crypto;

namespace MatterDevice.Commissioning.Pase;

/// <summary>The SPAKE2+ context label that prefixes the Matter PASE transcript context (Core Spec §4.14.1).</summary>
public static class PaseConstants
{
    public static readonly byte[] SpakeContextPrefix = Encoding.ASCII.GetBytes("CHIP PAKE V1 Commissioning");
    public const int MinPbkdfIterations = 1000;
    public const int MaxPbkdfIterations = 100_000;
    public const int MinSaltLength = 16;
    public const int MaxSaltLength = 32;
}

/// <summary>The session keys established by a successful PASE handshake.</summary>
public sealed record PaseSession(byte[] I2RKey, byte[] R2IKey, byte[] AttestationChallenge, ushort PeerSessionId, ushort LocalSessionId);

/// <summary>
/// The device (responder) side of a PASE handshake, as a transport-agnostic state machine operating on
/// the TLV payloads of the five PASE messages. Drive it in order:
/// <see cref="OnPbkdfParamRequest"/> → <see cref="OnPake1"/> → <see cref="OnPake3"/>. The SPAKE2+ math is
/// <see cref="Spake2Plus"/> (proven against the CHIP test vector); this class is the protocol plumbing:
/// message capture for the transcript context, key schedule, and confirmation-MAC verification.
/// </summary>
public sealed class PaseResponder
{
    private readonly Spake2Plus _spake = new();
    private readonly byte[] _w0;
    private readonly byte[] _l;
    private readonly byte[] _salt;
    private readonly int _iterations;
    private readonly ushort _localSessionId;

    // captured during the exchange
    private byte[] _pbkdfRequestBytes = [];
    private byte[] _pbkdfResponseBytes = [];
    private ushort _initiatorSessionId;
    private byte[] _y = [];
    private byte[] _bigY = [];
    private byte[] _expectedCa = [];
    private byte[] _ke = [];

    /// <summary>
    /// Creates a responder from the device's setup passcode (it derives and keeps only w0 and L = w1·P;
    /// the passcode is not retained). A production device would load a pre-provisioned {w0, L} verifier.
    /// </summary>
    public PaseResponder(uint passcode, byte[] salt, int iterations, ushort localSessionId)
    {
        if (salt.Length is < PaseConstants.MinSaltLength or > PaseConstants.MaxSaltLength)
            throw new ArgumentException($"Salt must be {PaseConstants.MinSaltLength}–{PaseConstants.MaxSaltLength} bytes.", nameof(salt));
        if (iterations is < PaseConstants.MinPbkdfIterations or > PaseConstants.MaxPbkdfIterations)
            throw new ArgumentOutOfRangeException(nameof(iterations));

        var (w0, w1) = Spake2Plus.ComputeW0W1(passcode, salt, iterations);
        _w0 = w0;
        _l = _spake.ComputeL(w1);
        _salt = salt;
        _iterations = iterations;
        _localSessionId = localSessionId;
    }

    /// <summary>Step 1: consume PBKDFParamRequest, return PBKDFParamResponse (both retained for the transcript).</summary>
    public PaseMessages.PbkdfParamResponse OnPbkdfParamRequest(ReadOnlySpan<byte> requestTlv)
    {
        _pbkdfRequestBytes = requestTlv.ToArray();
        var req = PaseMessages.PbkdfParamRequest.Decode(requestTlv);
        _initiatorSessionId = req.InitiatorSessionId;

        var resp = new PaseMessages.PbkdfParamResponse
        {
            InitiatorRandom = req.InitiatorRandom,
            ResponderRandom = RandomNumberGenerator.GetBytes(32),
            ResponderSessionId = _localSessionId,
            // hasPBKDFParameters inverts whether we disclose salt/iterations.
            Iterations = req.HasPbkdfParameters ? null : (uint)_iterations,
            Salt = req.HasPbkdfParameters ? null : _salt,
        };
        _pbkdfResponseBytes = resp.Encode();
        return resp;
    }

    /// <summary>Step 2: consume Pake1 (pA = X), return Pake2 (pB = Y, cB).</summary>
    public PaseMessages.Pake2 OnPake1(ReadOnlySpan<byte> pake1Tlv)
    {
        var pake1 = PaseMessages.Pake1.Decode(pake1Tlv);
        var x = pake1.PA;

        _y = Spake2Plus.RandomScalar();
        _bigY = _spake.ComputeY(_y, _w0);
        var (z, v) = _spake.ComputeVerifierZV(_y, x, _w0, _l);

        var context = BuildContext();
        var tt = Spake2Plus.BuildMatterTranscript(context, _spake.MUncompressed, _spake.NUncompressed, x, _bigY, z, v, _w0);
        var (ka, ke) = Spake2Plus.DeriveKaKe(tt);
        _ke = ke;
        var (kcA, kcB) = Spake2Plus.DeriveConfirmationKeys(ka);

        _expectedCa = Spake2Plus.ConfirmationMac(kcA, _bigY); // cA is HMAC(KcA, Y)
        var cB = Spake2Plus.ConfirmationMac(kcB, x);          // cB is HMAC(KcB, X)
        return new PaseMessages.Pake2 { PB = _bigY, CB = cB };
    }

    /// <summary>Step 3: consume Pake3 (cA). Returns the session on success, or null if confirmation fails.</summary>
    public PaseSession? OnPake3(ReadOnlySpan<byte> pake3Tlv)
    {
        var pake3 = PaseMessages.Pake3.Decode(pake3Tlv);
        if (!CryptographicOperations.FixedTimeEquals(pake3.CA, _expectedCa))
            return null;

        var (i2r, r2i, attest) = Spake2Plus.DeriveSessionKeys(_ke);
        return new PaseSession(i2r, r2i, attest, _initiatorSessionId, _localSessionId);
    }

    private byte[] BuildContext()
    {
        // Context = SHA-256( "CHIP PAKE V1 Commissioning" || PBKDFParamRequest || PBKDFParamResponse )
        using var sha = SHA256.Create();
        var buf = new byte[PaseConstants.SpakeContextPrefix.Length + _pbkdfRequestBytes.Length + _pbkdfResponseBytes.Length];
        var o = 0;
        PaseConstants.SpakeContextPrefix.CopyTo(buf, o); o += PaseConstants.SpakeContextPrefix.Length;
        _pbkdfRequestBytes.CopyTo(buf, o); o += _pbkdfRequestBytes.Length;
        _pbkdfResponseBytes.CopyTo(buf, o);
        return SHA256.HashData(buf);
    }
}

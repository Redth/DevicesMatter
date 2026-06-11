using System.Security.Cryptography;
using MatterDevice.Commissioning.Pase;
using MatterDevice.Core.Crypto;

namespace MatterDevice.Tests;

/// <summary>
/// A minimal commissioner-side PASE driver (the prover role) used by the tests to exercise the device
/// <see cref="PaseResponder"/>. A genuine controller (chip-tool, Apple Home, Home Assistant) plays this
/// same role on the wire.
/// </summary>
internal sealed class TestProver(uint passcode)
{
    private readonly Spake2Plus _spake = new();
    private readonly byte[] _initiatorRandom = RandomNumberGenerator.GetBytes(32);
    private byte[] _w0 = [], _w1 = [], _x = [], _bigX = [];
    private byte[] _reqBytes = [], _respBytes = [];

    public (byte[] I2R, byte[] R2I, byte[] Attest)? SessionKeys { get; private set; }
    public bool CbVerified { get; private set; }

    public byte[] BuildPbkdfParamRequest()
    {
        _reqBytes = new PaseMessages.PbkdfParamRequest
        {
            InitiatorRandom = _initiatorRandom,
            InitiatorSessionId = 0x4444,
            PasscodeId = 0,
            HasPbkdfParameters = false,
        }.Encode();
        return _reqBytes;
    }

    public void OnPbkdfParamResponse(byte[] reqBytes, byte[] respBytes)
    {
        _reqBytes = reqBytes;
        _respBytes = respBytes;
        var resp = PaseMessages.PbkdfParamResponse.Decode(respBytes);
        (_w0, _w1) = Spake2Plus.ComputeW0W1(passcode, resp.Salt!, (int)resp.Iterations!.Value);
    }

    public byte[] BuildPake1()
    {
        _x = Spake2Plus.RandomScalar();
        _bigX = _spake.ComputeX(_x, _w0);
        return new PaseMessages.Pake1 { PA = _bigX }.Encode();
    }

    public byte[] OnPake2BuildPake3(byte[] pake2Bytes, bool ignoreCbMismatch = false)
    {
        var pake2 = PaseMessages.Pake2.Decode(pake2Bytes);
        var y = pake2.PB;
        var (z, v) = _spake.ComputeProverZV(_x, _w1, y, _w0);

        var context = BuildContext();
        var tt = Spake2Plus.BuildMatterTranscript(context, _spake.MUncompressed, _spake.NUncompressed, _bigX, y, z, v, _w0);
        var (ka, ke) = Spake2Plus.DeriveKaKe(tt);
        var (kcA, kcB) = Spake2Plus.DeriveConfirmationKeys(ka);

        var expectedCb = Spake2Plus.ConfirmationMac(kcB, _bigX);
        CbVerified = CryptographicOperations.FixedTimeEquals(expectedCb, pake2.CB);
        if (!CbVerified && !ignoreCbMismatch)
            throw new InvalidOperationException("cB verification failed.");

        SessionKeys = Spake2Plus.DeriveSessionKeys(ke);
        var cA = Spake2Plus.ConfirmationMac(kcA, y);
        return new PaseMessages.Pake3 { CA = cA }.Encode();
    }

    private byte[] BuildContext()
    {
        var buf = new byte[PaseConstants.SpakeContextPrefix.Length + _reqBytes.Length + _respBytes.Length];
        var o = 0;
        PaseConstants.SpakeContextPrefix.CopyTo(buf, o); o += PaseConstants.SpakeContextPrefix.Length;
        _reqBytes.CopyTo(buf, o); o += _reqBytes.Length;
        _respBytes.CopyTo(buf, o);
        return SHA256.HashData(buf);
    }
}

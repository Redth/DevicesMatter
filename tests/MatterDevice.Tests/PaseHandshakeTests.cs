using System.Security.Cryptography;
using MatterDevice.Commissioning.Pase;
using MatterDevice.Core.Crypto;

namespace MatterDevice.Tests;

/// <summary>
/// End-to-end PASE: a commissioner (prover) harness drives the <see cref="PaseResponder"/> device through
/// all five messages over their TLV payloads, and both sides must independently derive the SAME session
/// keys (I2R / R2I / AttestationChallenge). This validates the whole handshake — message capture for the
/// transcript context, the SPAKE2+ exchange, confirmation MACs and the key schedule — not just the
/// isolated SPAKE2+ primitive. A genuine controller (chip-tool, Apple, HA) runs the same prover role.
/// </summary>
public class PaseHandshakeTests
{
    private const uint Passcode = 20202021;

    [Fact]
    public void Full_handshake_yields_matching_session_keys()
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        const int iterations = 1000;

        var device = new PaseResponder(Passcode, salt, iterations, localSessionId: 0x1111);
        var prover = new Prover(Passcode);

        // 1. PBKDFParamRequest → PBKDFParamResponse
        var reqBytes = prover.BuildPbkdfParamRequest();
        var respBytes = device.OnPbkdfParamRequest(reqBytes).Encode();
        prover.OnPbkdfParamResponse(reqBytes, respBytes);

        // 2. Pake1 → Pake2
        var pake1Bytes = prover.BuildPake1();
        var pake2Bytes = device.OnPake1(pake1Bytes).Encode();

        // 3. Pake3 → session
        var pake3Bytes = prover.OnPake2BuildPake3(pake2Bytes);
        var deviceSession = device.OnPake3(pake3Bytes);

        Assert.NotNull(deviceSession);
        var proverKeys = prover.SessionKeys;
        Assert.NotNull(proverKeys);

        // Both sides agree on every key — the shared secret matched.
        Assert.Equal(Convert.ToHexString(proverKeys!.Value.I2R), Convert.ToHexString(deviceSession!.I2RKey));
        Assert.Equal(Convert.ToHexString(proverKeys.Value.R2I), Convert.ToHexString(deviceSession.R2IKey));
        Assert.Equal(Convert.ToHexString(proverKeys.Value.Attest), Convert.ToHexString(deviceSession.AttestationChallenge));
        Assert.Equal((ushort)0x1111, deviceSession.LocalSessionId);
    }

    [Fact]
    public void Wrong_passcode_fails_confirmation()
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        const int iterations = 1000;

        var device = new PaseResponder(Passcode, salt, iterations, 0x2222);
        var prover = new Prover(passcode: 11223344); // mismatched

        var reqBytes = prover.BuildPbkdfParamRequest();
        var respBytes = device.OnPbkdfParamRequest(reqBytes).Encode();
        prover.OnPbkdfParamResponse(reqBytes, respBytes);

        var pake2Bytes = device.OnPake1(prover.BuildPake1()).Encode();
        var pake3Bytes = prover.OnPake2BuildPake3(pake2Bytes, ignoreCbMismatch: true);

        Assert.False(prover.CbVerified);                 // commissioner already detects the mismatch via cB
        Assert.Null(device.OnPake3(pake3Bytes));         // and the device rejects the wrong cA
    }

    /// <summary>A minimal commissioner-side PASE driver — the prover role — used only by these tests.</summary>
    private sealed class Prover(uint passcode)
    {
        private readonly Spake2Plus _spake = new();
        private readonly byte[] _initiatorRandom = RandomNumberGenerator.GetBytes(32);
        private byte[] _w0 = [], _w1 = [], _x = [], _bigX = [];
        private byte[] _reqBytes = [], _respBytes = [];

        public (byte[] I2R, byte[] R2I, byte[] Attest)? SessionKeys { get; private set; }

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

        public bool CbVerified { get; private set; }

        public byte[] OnPake2BuildPake3(byte[] pake2Bytes, bool ignoreCbMismatch = false)
        {
            var pake2 = PaseMessages.Pake2.Decode(pake2Bytes);
            var y = pake2.PB;
            var (z, v) = _spake.ComputeProverZV(_x, _w1, y, _w0);

            var context = BuildContext();
            var tt = Spake2Plus.BuildMatterTranscript(context, _spake.MUncompressed, _spake.NUncompressed, _bigX, y, z, v, _w0);
            var (ka, ke) = Spake2Plus.DeriveKaKe(tt);
            var (kcA, kcB) = Spake2Plus.DeriveConfirmationKeys(ka);

            // verify cB = HMAC(KcB, X)
            var expectedCb = Spake2Plus.ConfirmationMac(kcB, _bigX);
            CbVerified = CryptographicOperations.FixedTimeEquals(expectedCb, pake2.CB);
            if (!CbVerified && !ignoreCbMismatch)
                throw new InvalidOperationException("cB verification failed.");

            SessionKeys = Spake2Plus.DeriveSessionKeys(ke);
            var cA = Spake2Plus.ConfirmationMac(kcA, y); // cA = HMAC(KcA, Y)
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
}

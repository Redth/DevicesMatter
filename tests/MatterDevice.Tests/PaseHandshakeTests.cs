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
        var prover = new TestProver(Passcode);

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
        var prover = new TestProver(passcode: 11223344); // mismatched

        var reqBytes = prover.BuildPbkdfParamRequest();
        var respBytes = device.OnPbkdfParamRequest(reqBytes).Encode();
        prover.OnPbkdfParamResponse(reqBytes, respBytes);

        var pake2Bytes = device.OnPake1(prover.BuildPake1()).Encode();
        var pake3Bytes = prover.OnPake2BuildPake3(pake2Bytes, ignoreCbMismatch: true);

        Assert.False(prover.CbVerified);                 // commissioner already detects the mismatch via cB
        Assert.Null(device.OnPake3(pake3Bytes));         // and the device rejects the wrong cA
    }
}

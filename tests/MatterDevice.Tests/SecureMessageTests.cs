using System.Security.Cryptography;
using MatterDevice.Commissioning.Pase;
using MatterDevice.Core.Crypto;
using MatterDevice.Core.Messaging;

namespace MatterDevice.Tests;

/// <summary>
/// Exercises the AES-CCM secure message path (Matter Core Spec §4.7): a message encrypted with one of the
/// PASE-derived session keys decrypts back to the same protocol header + payload with the matching key,
/// and tampering (or the wrong key) is rejected by the authentication tag.
/// </summary>
public class SecureMessageTests
{
    [Fact]
    public void Secure_message_round_trips_with_pase_session_key()
    {
        var key = EstablishSessionKey(out _);

        var original = new MatterMessage
        {
            SessionId = 0x1001, // a secure (non-zero) session
            SecurityFlags = 0,
            MessageCounter = 0x00ABCDEF,
            SourceNodeId = 0x1122334455667788,
            IsInitiator = false,
            Opcode = 0x05,
            ExchangeId = 0x2222,
            ProtocolId = MatterProtocolId.InteractionModel,
            Payload = [0x15, 0x24, 0x00, 0x01, 0x18],
        };

        var wire = original.EncodeSecure(key);
        // Only the 16-byte message header is plaintext; the rest is ciphertext + 16-byte tag.
        var header = original.EncodeMessageHeader();
        var innerPlain = original.EncodeProtocolPayload();
        Assert.Equal(header.Length + innerPlain.Length + MatterAead.TagLength, wire.Length);

        var decoded = MatterMessage.DecodeSecure(wire, key);
        Assert.Equal(original.Opcode, decoded.Opcode);
        Assert.Equal(original.ExchangeId, decoded.ExchangeId);
        Assert.Equal(MatterProtocolId.InteractionModel, decoded.ProtocolId);
        Assert.Equal(original.Payload, decoded.Payload);
        Assert.Equal(original.SessionId, decoded.SessionId);
        Assert.Equal(original.MessageCounter, decoded.MessageCounter);
    }

    [Fact]
    public void Tampered_ciphertext_is_rejected()
    {
        var key = EstablishSessionKey(out _);
        var msg = new MatterMessage { SessionId = 1, MessageCounter = 7, SourceNodeId = 1, Opcode = 1, Payload = [1, 2, 3] };
        var wire = msg.EncodeSecure(key);
        wire[^1] ^= 0xFF; // flip a tag byte

        Assert.Throws<AeadAuthenticationException>(() => MatterMessage.DecodeSecure(wire, key));
    }

    [Fact]
    public void Wrong_key_is_rejected()
    {
        var key = EstablishSessionKey(out _);
        var msg = new MatterMessage { SessionId = 1, MessageCounter = 7, SourceNodeId = 1, Opcode = 1, Payload = [1, 2, 3] };
        var wire = msg.EncodeSecure(key);

        var wrongKey = RandomNumberGenerator.GetBytes(16);
        Assert.Throws<AeadAuthenticationException>(() => MatterMessage.DecodeSecure(wire, wrongKey));
    }

    [Fact]
    public void Device_and_peer_can_exchange_using_directional_keys()
    {
        // The device encrypts outbound with R2I and decrypts inbound with I2R; the peer mirrors. Prove a
        // message sealed under R2I is readable with R2I (same directional key on both ends).
        var i2r = EstablishSessionKey(out var r2i);

        var fromDevice = new MatterMessage { SessionId = 5, MessageCounter = 1, SourceNodeId = 9, Opcode = 0x08, Payload = [9, 9] };
        var wire = fromDevice.EncodeSecure(r2i);
        var atPeer = MatterMessage.DecodeSecure(wire, r2i);
        Assert.Equal(fromDevice.Payload, atPeer.Payload);

        // and the I2R key (the other direction) must NOT open it
        Assert.Throws<AeadAuthenticationException>(() => MatterMessage.DecodeSecure(wire, i2r));
    }

    /// <summary>Runs a real PASE handshake and returns the I2R key (and R2I via out) for these tests.</summary>
    private static byte[] EstablishSessionKey(out byte[] r2i)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var device = new PaseResponder(20202021, salt, 1000, 0x0001);
        var prover = new TestProver(20202021);

        var reqBytes = prover.BuildPbkdfParamRequest();
        var respBytes = device.OnPbkdfParamRequest(reqBytes).Encode();
        prover.OnPbkdfParamResponse(reqBytes, respBytes);
        var pake2 = device.OnPake1(prover.BuildPake1());
        var pake3 = prover.OnPake2BuildPake3(pake2.Encode());
        var session = device.OnPake3(pake3);

        Assert.NotNull(session);
        r2i = session!.R2IKey;
        return session.I2RKey;
    }
}

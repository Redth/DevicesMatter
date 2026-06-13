using System.Security.Cryptography;
using MatterDevice.Core.Crypto;
using MatterDevice.Core.Messaging;

namespace MatterDevice.Core.Session;

/// <summary>How a secure session was established.</summary>
public enum SessionOrigin { Pase, Case }

/// <summary>
/// An established secure session (Matter Core Spec §4.12 / §4.6): the directional AES-CCM keys, the local
/// and peer session ids and node ids, an outbound message counter, and the inbound de-duplication state.
/// The device decrypts inbound with <see cref="DecryptKey"/> and encrypts outbound with
/// <see cref="EncryptKey"/>; for a device (responder) those are the I2R and R2I keys respectively.
/// </summary>
public sealed class SecureSession
{
    public required ushort LocalSessionId { get; init; }
    public required ushort PeerSessionId { get; init; }
    public ulong PeerNodeId { get; init; }
    public ulong LocalNodeId { get; init; }
    public SessionOrigin Origin { get; init; }

    /// <summary>Key for decrypting inbound messages (I2R for a device responder).</summary>
    public required byte[] DecryptKey { get; init; }

    /// <summary>Key for encrypting outbound messages (R2I for a device responder).</summary>
    public required byte[] EncryptKey { get; init; }

    public byte[] AttestationChallenge { get; init; } = [];

    /// <summary>An opaque transport token for the peer (e.g. its UDP endpoint), used to push async reports.</summary>
    public object? Peer { get; set; }

    private uint _outboundCounter = (BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4)) >> 4) + 1;
    private readonly MessageReceptionState _reception = new();

    /// <summary>The next outbound message counter for this session.</summary>
    public uint NextOutboundCounter() => _outboundCounter++;

    /// <summary>Classifies an inbound counter for de-duplication.</summary>
    public MessageReceptionState.Result AcceptInbound(uint counter) => _reception.Process(counter);

    /// <summary>Encrypts a message for this session (sets session id + counter and seals with the encrypt key).</summary>
    public byte[] Encode(MatterMessage message)
    {
        message.SessionId = PeerSessionId; // peer indexes the session by the id it allocated
        message.MessageCounter = NextOutboundCounter();
        return message.EncodeSecure(EncryptKey);
    }

    /// <summary>Decrypts an inbound message for this session (peer node id fills the nonce when omitted).</summary>
    public MatterMessage Decode(ReadOnlySpan<byte> data) => MatterMessage.DecodeSecure(data, DecryptKey, PeerNodeId);
}

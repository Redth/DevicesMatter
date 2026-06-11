using System.Buffers.Binary;
using MatterDevice.Core.Crypto;

namespace MatterDevice.Core.Messaging;

/// <summary>
/// A Matter message frame (Matter Core Spec §4.4): the unencrypted message header, the protocol
/// (payload) header, and the application payload. All multi-byte integers are little-endian.
/// </summary>
/// <remarks>
/// This models the wire format used during PASE, which runs over the <b>unsecured session</b>
/// (Session ID 0, no encryption, no MIC). Encode/Decode here handle the plaintext path; the encrypted
/// path (AES-CCM with the AAD = header bytes and the 13-byte nonce) is a documented follow-on and not
/// needed to begin commissioning.
/// </remarks>
public sealed class MatterMessage
{
    // ---- message header --------------------------------------------------

    /// <summary>Session ID (0x0000 = the unsecured session used by PASE).</summary>
    public ushort SessionId { get; set; }

    /// <summary>Raw security flags byte (P/C/MX + session type). 0x00 for unsecured unicast.</summary>
    public byte SecurityFlags { get; set; }

    /// <summary>Per-sender message counter.</summary>
    public uint MessageCounter { get; set; }

    /// <summary>Source Node ID, present iff set (the S flag is emitted when non-null).</summary>
    public ulong? SourceNodeId { get; set; }

    /// <summary>Destination Node ID (DSIZ = 1 when present). Group destinations are not modeled here.</summary>
    public ulong? DestinationNodeId { get; set; }

    // ---- protocol (payload) header --------------------------------------

    public bool IsInitiator { get; set; }
    public bool IsAck { get; set; }
    public bool RequiresAck { get; set; }
    public uint? AckedMessageCounter { get; set; }

    public byte Opcode { get; set; }
    public ushort ExchangeId { get; set; }
    public MatterProtocolId ProtocolId { get; set; } = MatterProtocolId.SecureChannel;

    /// <summary>The application payload (typically TLV).</summary>
    public byte[] Payload { get; set; } = [];

    private const byte MsgFlagSourcePresent = 0x04;
    private const byte ExFlagInitiator = 0x01;
    private const byte ExFlagAck = 0x02;
    private const byte ExFlagReliability = 0x04;
    private const byte ExFlagVendor = 0x10;

    /// <summary>Serializes the frame to its on-wire bytes (unsecured/plaintext path).</summary>
    public byte[] Encode()
    {
        var buf = new ArrayWriter();
        WriteMessageHeader(buf);
        WriteProtocolHeaderAndPayload(buf);
        return buf.ToArray();
    }

    /// <summary>
    /// The unencrypted message header (Matter Core Spec §4.4.1): message flags, session id, security
    /// flags, counter, and any source/destination node ids. For a secure message these bytes are the
    /// AEAD additional-authenticated-data; the protocol header + payload are what gets encrypted.
    /// </summary>
    public byte[] EncodeMessageHeader()
    {
        var buf = new ArrayWriter();
        WriteMessageHeader(buf);
        return buf.ToArray();
    }

    /// <summary>The protocol header + application payload — the plaintext that the secure path encrypts.</summary>
    public byte[] EncodeProtocolPayload()
    {
        var buf = new ArrayWriter();
        WriteProtocolHeaderAndPayload(buf);
        return buf.ToArray();
    }

    private void WriteMessageHeader(ArrayWriter buf)
    {
        byte msgFlags = 0x00; // version 0, DSIZ depends on destination
        if (SourceNodeId.HasValue) msgFlags |= MsgFlagSourcePresent;
        if (DestinationNodeId.HasValue) msgFlags |= 0x01; // DSIZ = 1 (64-bit node id)
        buf.WriteByte(msgFlags);
        buf.WriteUInt16(SessionId);
        buf.WriteByte(SecurityFlags);
        buf.WriteUInt32(MessageCounter);
        if (SourceNodeId.HasValue) buf.WriteUInt64(SourceNodeId.Value);
        if (DestinationNodeId.HasValue) buf.WriteUInt64(DestinationNodeId.Value);
    }

    private void WriteProtocolHeaderAndPayload(ArrayWriter buf)
    {
        byte exFlags = 0x00;
        if (IsInitiator) exFlags |= ExFlagInitiator;
        if (IsAck) exFlags |= ExFlagAck;
        if (RequiresAck) exFlags |= ExFlagReliability;
        buf.WriteByte(exFlags);
        buf.WriteByte(Opcode);
        buf.WriteUInt16(ExchangeId);
        buf.WriteUInt16((ushort)ProtocolId);
        if (IsAck)
            buf.WriteUInt32(AckedMessageCounter ?? 0);
        buf.WriteBytes(Payload);
    }

    /// <summary>
    /// The 13-byte AEAD nonce (Matter Core Spec §4.7.2): security flags ‖ message counter (LE) ‖ source
    /// node id (LE). For a message with no source node id, zero is used.
    /// </summary>
    public byte[] BuildNonce()
    {
        var nonce = new byte[13];
        nonce[0] = SecurityFlags;
        BinaryPrimitives.WriteUInt32LittleEndian(nonce.AsSpan(1), MessageCounter);
        BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan(5), SourceNodeId ?? 0);
        return nonce;
    }

    /// <summary>Parses an on-wire frame (unsecured/plaintext path).</summary>
    public static MatterMessage Decode(ReadOnlySpan<byte> data)
    {
        var (msg, headerLen) = DecodeMessageHeader(data);
        msg.ParseProtocolPayload(data.Slice(headerLen));
        return msg;
    }

    /// <summary>
    /// Serializes the frame as an encrypted (secure-session) message: the plaintext message header
    /// followed by AES-CCM(protocol header ‖ payload) ‖ tag, with AAD = the message header and the nonce
    /// built from this message's security flags / counter / source node id.
    /// </summary>
    public byte[] EncodeSecure(ReadOnlySpan<byte> key)
    {
        var header = EncodeMessageHeader();
        var inner = EncodeProtocolPayload();
        var sealed_ = MatterAead.Encrypt(key, BuildNonce(), inner, header);

        var output = new byte[header.Length + sealed_.Length];
        header.CopyTo(output, 0);
        sealed_.CopyTo(output, header.Length);
        return output;
    }

    /// <summary>
    /// Parses and decrypts a secure-session frame with <paramref name="key"/>. Throws if the
    /// authentication tag does not verify.
    /// </summary>
    public static MatterMessage DecodeSecure(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key)
    {
        var (msg, headerLen) = DecodeMessageHeader(data);
        var header = data[..headerLen];
        var ciphertextAndTag = data[headerLen..];
        var plaintext = MatterAead.Decrypt(key, msg.BuildNonce(), ciphertextAndTag, header);
        msg.ParseProtocolPayload(plaintext);
        return msg;
    }

    /// <summary>
    /// Parses just the message header, returning the populated message (header fields only) and the
    /// header length. For a secure message, <c>data[0..headerLen]</c> is the AEAD AAD and the rest is the
    /// ciphertext + tag.
    /// </summary>
    public static (MatterMessage Message, int HeaderLength) DecodeMessageHeader(ReadOnlySpan<byte> data)
    {
        var msg = new MatterMessage();
        var pos = 0;

        var msgFlags = data[pos++];
        var dsiz = msgFlags & 0x03;
        msg.SessionId = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(pos)); pos += 2;
        msg.SecurityFlags = data[pos++];
        msg.MessageCounter = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(pos)); pos += 4;

        if ((msgFlags & MsgFlagSourcePresent) != 0)
        {
            msg.SourceNodeId = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(pos)); pos += 8;
        }
        switch (dsiz)
        {
            case 1:
                msg.DestinationNodeId = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(pos)); pos += 8;
                break;
            case 2:
                pos += 2; // group id — not modeled
                break;
        }
        return (msg, pos);
    }

    /// <summary>Parses the protocol header + application payload (the decrypted plaintext for a secure message).</summary>
    public void ParseProtocolPayload(ReadOnlySpan<byte> inner)
    {
        var pos = 0;
        var exFlags = inner[pos++];
        IsInitiator = (exFlags & ExFlagInitiator) != 0;
        IsAck = (exFlags & ExFlagAck) != 0;
        RequiresAck = (exFlags & ExFlagReliability) != 0;
        Opcode = inner[pos++];
        ExchangeId = BinaryPrimitives.ReadUInt16LittleEndian(inner.Slice(pos)); pos += 2;
        if ((exFlags & ExFlagVendor) != 0)
            pos += 2; // vendor id — standard vendor assumed
        ProtocolId = (MatterProtocolId)BinaryPrimitives.ReadUInt16LittleEndian(inner.Slice(pos)); pos += 2;
        if (IsAck)
        {
            AckedMessageCounter = BinaryPrimitives.ReadUInt32LittleEndian(inner.Slice(pos)); pos += 4;
        }
        Payload = inner.Slice(pos).ToArray();
    }

    /// <summary>Minimal growable little-endian writer used by <see cref="Encode"/>.</summary>
    private sealed class ArrayWriter
    {
        private byte[] _b = new byte[64];
        private int _n;

        public void WriteByte(byte v) { Ensure(1); _b[_n++] = v; }
        public void WriteUInt16(ushort v) { Ensure(2); BinaryPrimitives.WriteUInt16LittleEndian(_b.AsSpan(_n), v); _n += 2; }
        public void WriteUInt32(uint v) { Ensure(4); BinaryPrimitives.WriteUInt32LittleEndian(_b.AsSpan(_n), v); _n += 4; }
        public void WriteUInt64(ulong v) { Ensure(8); BinaryPrimitives.WriteUInt64LittleEndian(_b.AsSpan(_n), v); _n += 8; }
        public void WriteBytes(ReadOnlySpan<byte> v) { Ensure(v.Length); v.CopyTo(_b.AsSpan(_n)); _n += v.Length; }
        public byte[] ToArray() => _b.AsSpan(0, _n).ToArray();

        private void Ensure(int extra)
        {
            if (_n + extra > _b.Length)
                Array.Resize(ref _b, Math.Max(_b.Length * 2, _n + extra));
        }
    }
}

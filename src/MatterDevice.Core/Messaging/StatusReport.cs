using System.Buffers.Binary;

namespace MatterDevice.Core.Messaging;

/// <summary>
/// A Secure Channel StatusReport payload (Matter Core Spec §4.13.2.4): GeneralStatusCode (2),
/// ProtocolId (4), ProtocolCode (2), then optional ProtocolData. PASE/CASE signal success or failure
/// with this rather than a dedicated opcode.
/// </summary>
public sealed class StatusReport
{
    public GeneralStatusCode GeneralStatus { get; set; }
    public MatterProtocolId Protocol { get; set; } = MatterProtocolId.SecureChannel;
    public ushort ProtocolCode { get; set; }

    public static StatusReport SessionEstablished() => new()
    {
        GeneralStatus = GeneralStatusCode.Success,
        Protocol = MatterProtocolId.SecureChannel,
        ProtocolCode = (ushort)SecureChannelStatusCode.SessionEstablishmentSuccess,
    };

    public static StatusReport Failure(SecureChannelStatusCode code) => new()
    {
        GeneralStatus = GeneralStatusCode.Failure,
        Protocol = MatterProtocolId.SecureChannel,
        ProtocolCode = (ushort)code,
    };

    public byte[] Encode()
    {
        var b = new byte[8];
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(0), (ushort)GeneralStatus);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(2), (ushort)Protocol);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(6), ProtocolCode);
        return b;
    }

    public static StatusReport Decode(ReadOnlySpan<byte> data) => new()
    {
        GeneralStatus = (GeneralStatusCode)BinaryPrimitives.ReadUInt16LittleEndian(data),
        Protocol = (MatterProtocolId)BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(2)),
        ProtocolCode = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(6)),
    };
}

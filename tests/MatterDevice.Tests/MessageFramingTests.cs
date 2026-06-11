using MatterDevice.Core.Messaging;
using MatterDevice.Core.Tlv;

namespace MatterDevice.Tests;

public class MessageFramingTests
{
    [Fact]
    public void Unsecured_pase_message_round_trips()
    {
        var original = new MatterMessage
        {
            SessionId = 0, // unsecured session
            SecurityFlags = 0,
            MessageCounter = 0x01020304,
            SourceNodeId = 0xAABBCCDDEEFF0011,
            IsInitiator = true,
            RequiresAck = true,
            Opcode = (byte)SecureChannelOpcode.PbkdfParamRequest,
            ExchangeId = 0x1234,
            ProtocolId = MatterProtocolId.SecureChannel,
            Payload = [0x15, 0x18], // empty TLV struct
        };

        var wire = original.Encode();
        var decoded = MatterMessage.Decode(wire);

        Assert.Equal(original.SessionId, decoded.SessionId);
        Assert.Equal(original.MessageCounter, decoded.MessageCounter);
        Assert.Equal(original.SourceNodeId, decoded.SourceNodeId);
        Assert.Null(decoded.DestinationNodeId);
        Assert.True(decoded.IsInitiator);
        Assert.True(decoded.RequiresAck);
        Assert.Equal(original.Opcode, decoded.Opcode);
        Assert.Equal(original.ExchangeId, decoded.ExchangeId);
        Assert.Equal(MatterProtocolId.SecureChannel, decoded.ProtocolId);
        Assert.Equal(original.Payload, decoded.Payload);
    }

    [Fact]
    public void Ack_message_carries_acked_counter()
    {
        var msg = new MatterMessage
        {
            SessionId = 0,
            MessageCounter = 5,
            IsAck = true,
            AckedMessageCounter = 42,
            Opcode = (byte)SecureChannelOpcode.StandaloneAck,
        };

        var decoded = MatterMessage.Decode(msg.Encode());
        Assert.True(decoded.IsAck);
        Assert.Equal((ushort?)42, decoded.AckedMessageCounter);
    }

    [Fact]
    public void Tlv_struct_round_trips_context_fields()
    {
        var w = new TlvWriter();
        w.StartStructure(TlvTag.Anonymous)
            .WriteUInt(TlvTag.ContextSpecific(1), 0xDEADBEEF)
            .WriteBytes(TlvTag.ContextSpecific(2), [1, 2, 3, 4, 5])
            .WriteBool(TlvTag.ContextSpecific(3), true)
            .EndContainer();

        var reader = new TlvReader(w.WrittenSpan);
        Assert.True(reader.Read());
        Assert.True(reader.IsContainer);

        ulong? f1 = null;
        byte[]? f2 = null;
        bool? f3 = null;
        reader.EnterContainer((ref TlvReader r) =>
        {
            switch (r.TagNumber)
            {
                case 1: f1 = r.GetUInt(); break;
                case 2: f2 = r.GetBytes().ToArray(); break;
                case 3: f3 = r.GetBool(); break;
            }
        });

        Assert.Equal(0xDEADBEEFul, f1);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, f2);
        Assert.True(f3);
    }
}

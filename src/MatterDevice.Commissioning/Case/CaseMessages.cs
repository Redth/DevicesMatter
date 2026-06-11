using MatterDevice.Core.Tlv;

namespace MatterDevice.Commissioning.Case;

/// <summary>
/// TLV codecs for the CASE Sigma messages and their to-be-encrypted / to-be-signed structures
/// (Matter Core Spec §4.14.2). Each is a single anonymous top-level structure with context-tagged fields.
/// </summary>
public static class CaseMessages
{
    // ---- Sigma1 (initiator → responder) ---------------------------------

    public sealed class Sigma1
    {
        public byte[] InitiatorRandom { get; set; } = [];
        public ushort InitiatorSessionId { get; set; }
        public byte[] DestinationId { get; set; } = [];
        public byte[] InitiatorEphPublicKey { get; set; } = [];

        public byte[] Encode()
        {
            var w = new TlvWriter();
            w.StartStructure(TlvTag.Anonymous)
                .WriteBytes(TlvTag.ContextSpecific(1), InitiatorRandom)
                .WriteUInt(TlvTag.ContextSpecific(2), InitiatorSessionId)
                .WriteBytes(TlvTag.ContextSpecific(3), DestinationId)
                .WriteBytes(TlvTag.ContextSpecific(4), InitiatorEphPublicKey)
                .EndContainer();
            return w.ToArray();
        }

        public static Sigma1 Decode(ReadOnlySpan<byte> tlv)
        {
            var m = new Sigma1();
            var r = new TlvReader(tlv);
            if (!r.Read() || !r.IsContainer) throw new FormatException("Sigma1: expected a struct.");
            r.EnterContainer((ref TlvReader f) =>
            {
                switch (f.TagNumber)
                {
                    case 1: m.InitiatorRandom = f.GetBytes().ToArray(); break;
                    case 2: m.InitiatorSessionId = (ushort)f.GetUInt(); break;
                    case 3: m.DestinationId = f.GetBytes().ToArray(); break;
                    case 4: m.InitiatorEphPublicKey = f.GetBytes().ToArray(); break;
                }
            });
            return m;
        }
    }

    // ---- Sigma2 (responder → initiator) ---------------------------------

    public sealed class Sigma2
    {
        public byte[] ResponderRandom { get; set; } = [];
        public ushort ResponderSessionId { get; set; }
        public byte[] ResponderEphPublicKey { get; set; } = [];
        public byte[] Encrypted2 { get; set; } = [];

        public byte[] Encode()
        {
            var w = new TlvWriter();
            w.StartStructure(TlvTag.Anonymous)
                .WriteBytes(TlvTag.ContextSpecific(1), ResponderRandom)
                .WriteUInt(TlvTag.ContextSpecific(2), ResponderSessionId)
                .WriteBytes(TlvTag.ContextSpecific(3), ResponderEphPublicKey)
                .WriteBytes(TlvTag.ContextSpecific(4), Encrypted2)
                .EndContainer();
            return w.ToArray();
        }

        public static Sigma2 Decode(ReadOnlySpan<byte> tlv)
        {
            var m = new Sigma2();
            var r = new TlvReader(tlv);
            if (!r.Read() || !r.IsContainer) throw new FormatException("Sigma2: expected a struct.");
            r.EnterContainer((ref TlvReader f) =>
            {
                switch (f.TagNumber)
                {
                    case 1: m.ResponderRandom = f.GetBytes().ToArray(); break;
                    case 2: m.ResponderSessionId = (ushort)f.GetUInt(); break;
                    case 3: m.ResponderEphPublicKey = f.GetBytes().ToArray(); break;
                    case 4: m.Encrypted2 = f.GetBytes().ToArray(); break;
                }
            });
            return m;
        }
    }

    // ---- Sigma3 (initiator → responder) ---------------------------------

    public sealed class Sigma3
    {
        public byte[] Encrypted3 { get; set; } = [];

        public byte[] Encode()
        {
            var w = new TlvWriter();
            w.StartStructure(TlvTag.Anonymous).WriteBytes(TlvTag.ContextSpecific(1), Encrypted3).EndContainer();
            return w.ToArray();
        }

        public static Sigma3 Decode(ReadOnlySpan<byte> tlv)
        {
            var m = new Sigma3();
            var r = new TlvReader(tlv);
            if (!r.Read() || !r.IsContainer) throw new FormatException("Sigma3: expected a struct.");
            r.EnterContainer((ref TlvReader f) => { if (f.TagNumber == 1) m.Encrypted3 = f.GetBytes().ToArray(); });
            return m;
        }
    }

    // ---- TBEData / TBSData (NOC ‖ ICAC? ‖ signature ‖ …) -----------------

    /// <summary>Builds the to-be-signed structure { 1:noc, 2:icac?, 3:senderEph, 4:receiverEph } (Sigma2/Sigma3).</summary>
    public static byte[] EncodeTbsData(byte[] noc, byte[]? icac, byte[] senderEphPublicKey, byte[] receiverEphPublicKey)
    {
        var w = new TlvWriter();
        w.StartStructure(TlvTag.Anonymous);
        w.WriteBytes(TlvTag.ContextSpecific(1), noc);
        if (icac is not null) w.WriteBytes(TlvTag.ContextSpecific(2), icac);
        w.WriteBytes(TlvTag.ContextSpecific(3), senderEphPublicKey);
        w.WriteBytes(TlvTag.ContextSpecific(4), receiverEphPublicKey);
        w.EndContainer();
        return w.ToArray();
    }

    /// <summary>Builds the to-be-encrypted structure for Sigma2 { 1:noc, 2:icac?, 3:signature, 4:resumptionId }.</summary>
    public static byte[] EncodeTbeData2(byte[] noc, byte[]? icac, byte[] signature, byte[] resumptionId)
    {
        var w = new TlvWriter();
        w.StartStructure(TlvTag.Anonymous);
        w.WriteBytes(TlvTag.ContextSpecific(1), noc);
        if (icac is not null) w.WriteBytes(TlvTag.ContextSpecific(2), icac);
        w.WriteBytes(TlvTag.ContextSpecific(3), signature);
        w.WriteBytes(TlvTag.ContextSpecific(4), resumptionId);
        w.EndContainer();
        return w.ToArray();
    }

    /// <summary>Builds the to-be-encrypted structure for Sigma3 { 1:noc, 2:icac?, 3:signature }.</summary>
    public static byte[] EncodeTbeData3(byte[] noc, byte[]? icac, byte[] signature)
    {
        var w = new TlvWriter();
        w.StartStructure(TlvTag.Anonymous);
        w.WriteBytes(TlvTag.ContextSpecific(1), noc);
        if (icac is not null) w.WriteBytes(TlvTag.ContextSpecific(2), icac);
        w.WriteBytes(TlvTag.ContextSpecific(3), signature);
        w.EndContainer();
        return w.ToArray();
    }

    /// <summary>The decoded fields of a TBEData structure (NOC ‖ ICAC? ‖ signature ‖ resumptionId?).</summary>
    public sealed record TbeData(byte[] Noc, byte[]? Icac, byte[] Signature, byte[]? ResumptionId);

    public static TbeData DecodeTbeData(ReadOnlySpan<byte> tlv)
    {
        byte[] noc = [], signature = [];
        byte[]? icac = null, resumptionId = null;
        var r = new TlvReader(tlv);
        if (!r.Read() || !r.IsContainer) throw new FormatException("TBEData: expected a struct.");
        r.EnterContainer((ref TlvReader f) =>
        {
            switch (f.TagNumber)
            {
                case 1: noc = f.GetBytes().ToArray(); break;
                case 2: icac = f.GetBytes().ToArray(); break;
                case 3: signature = f.GetBytes().ToArray(); break;
                case 4: resumptionId = f.GetBytes().ToArray(); break;
            }
        });
        return new TbeData(noc, icac, signature, resumptionId);
    }
}

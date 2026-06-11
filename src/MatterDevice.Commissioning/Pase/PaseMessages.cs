using MatterDevice.Core.Tlv;

namespace MatterDevice.Commissioning.Pase;

/// <summary>
/// TLV codecs for the five PASE messages (Matter Core Spec §4.14.1). Each message is a single anonymous
/// top-level structure whose fields carry context-specific tags. The exact on-wire bytes of
/// PBKDFParamRequest/Response are retained by callers because they feed the SPAKE2+ transcript context.
/// </summary>
public static class PaseMessages
{
    // ---- PBKDFParamRequest (0x20) ---------------------------------------

    public sealed class PbkdfParamRequest
    {
        public byte[] InitiatorRandom { get; set; } = [];
        public ushort InitiatorSessionId { get; set; }
        public ushort PasscodeId { get; set; }
        public bool HasPbkdfParameters { get; set; }

        public byte[] Encode()
        {
            var w = new TlvWriter();
            w.StartStructure(TlvTag.Anonymous)
                .WriteBytes(TlvTag.ContextSpecific(1), InitiatorRandom)
                .WriteUInt(TlvTag.ContextSpecific(2), InitiatorSessionId)
                .WriteUInt(TlvTag.ContextSpecific(3), PasscodeId)
                .WriteBool(TlvTag.ContextSpecific(4), HasPbkdfParameters)
                .EndContainer();
            return w.ToArray();
        }

        public static PbkdfParamRequest Decode(ReadOnlySpan<byte> tlv)
        {
            var msg = new PbkdfParamRequest();
            var r = new TlvReader(tlv);
            if (!r.Read() || !r.IsContainer) throw new FormatException("PBKDFParamRequest: expected a struct.");
            r.EnterContainer((ref TlvReader f) =>
            {
                switch (f.TagNumber)
                {
                    case 1: msg.InitiatorRandom = f.GetBytes().ToArray(); break;
                    case 2: msg.InitiatorSessionId = (ushort)f.GetUInt(); break;
                    case 3: msg.PasscodeId = (ushort)f.GetUInt(); break;
                    case 4: msg.HasPbkdfParameters = f.GetBool(); break;
                }
            });
            return msg;
        }
    }

    // ---- PBKDFParamResponse (0x21) --------------------------------------

    public sealed class PbkdfParamResponse
    {
        public byte[] InitiatorRandom { get; set; } = [];
        public byte[] ResponderRandom { get; set; } = [];
        public ushort ResponderSessionId { get; set; }

        /// <summary>Included only when the request had <c>hasPBKDFParameters == false</c>.</summary>
        public uint? Iterations { get; set; }
        public byte[]? Salt { get; set; }

        public byte[] Encode()
        {
            var w = new TlvWriter();
            w.StartStructure(TlvTag.Anonymous)
                .WriteBytes(TlvTag.ContextSpecific(1), InitiatorRandom)
                .WriteBytes(TlvTag.ContextSpecific(2), ResponderRandom)
                .WriteUInt(TlvTag.ContextSpecific(3), ResponderSessionId);
            if (Iterations.HasValue && Salt is not null)
            {
                w.StartStructure(TlvTag.ContextSpecific(4))
                    .WriteUInt(TlvTag.ContextSpecific(1), Iterations.Value)
                    .WriteBytes(TlvTag.ContextSpecific(2), Salt)
                    .EndContainer();
            }
            w.EndContainer();
            return w.ToArray();
        }

        public static PbkdfParamResponse Decode(ReadOnlySpan<byte> tlv)
        {
            var msg = new PbkdfParamResponse();
            uint? iterations = null;
            byte[]? salt = null;

            var r = new TlvReader(tlv);
            if (!r.Read() || !r.IsContainer) throw new FormatException("PBKDFParamResponse: expected a struct.");
            r.EnterContainer((ref TlvReader f) =>
            {
                switch (f.TagNumber)
                {
                    case 1: msg.InitiatorRandom = f.GetBytes().ToArray(); break;
                    case 2: msg.ResponderRandom = f.GetBytes().ToArray(); break;
                    case 3: msg.ResponderSessionId = (ushort)f.GetUInt(); break;
                    case 4 when f.IsContainer:
                        // pbkdfParameters { 1: iterations, 2: salt }
                        var captured = (Iter: (uint?)null, Salt: (byte[]?)null);
                        f.EnterContainer((ref TlvReader p) =>
                        {
                            switch (p.TagNumber)
                            {
                                case 1: captured.Iter = (uint)p.GetUInt(); break;
                                case 2: captured.Salt = p.GetBytes().ToArray(); break;
                            }
                        });
                        iterations = captured.Iter;
                        salt = captured.Salt;
                        break;
                }
            });
            msg.Iterations = iterations;
            msg.Salt = salt;
            return msg;
        }
    }

    // ---- Pake1 / Pake2 / Pake3 ------------------------------------------

    public sealed class Pake1
    {
        public byte[] PA { get; set; } = []; // X (65 bytes)

        public byte[] Encode()
        {
            var w = new TlvWriter();
            w.StartStructure(TlvTag.Anonymous).WriteBytes(TlvTag.ContextSpecific(1), PA).EndContainer();
            return w.ToArray();
        }

        public static Pake1 Decode(ReadOnlySpan<byte> tlv)
        {
            var msg = new Pake1();
            var r = new TlvReader(tlv);
            if (!r.Read() || !r.IsContainer) throw new FormatException("Pake1: expected a struct.");
            r.EnterContainer((ref TlvReader f) => { if (f.TagNumber == 1) msg.PA = f.GetBytes().ToArray(); });
            return msg;
        }
    }

    public sealed class Pake2
    {
        public byte[] PB { get; set; } = []; // Y (65 bytes)
        public byte[] CB { get; set; } = []; // device confirmation (32 bytes)

        public byte[] Encode()
        {
            var w = new TlvWriter();
            w.StartStructure(TlvTag.Anonymous)
                .WriteBytes(TlvTag.ContextSpecific(1), PB)
                .WriteBytes(TlvTag.ContextSpecific(2), CB)
                .EndContainer();
            return w.ToArray();
        }

        public static Pake2 Decode(ReadOnlySpan<byte> tlv)
        {
            var msg = new Pake2();
            var r = new TlvReader(tlv);
            if (!r.Read() || !r.IsContainer) throw new FormatException("Pake2: expected a struct.");
            r.EnterContainer((ref TlvReader f) =>
            {
                switch (f.TagNumber)
                {
                    case 1: msg.PB = f.GetBytes().ToArray(); break;
                    case 2: msg.CB = f.GetBytes().ToArray(); break;
                }
            });
            return msg;
        }
    }

    public sealed class Pake3
    {
        public byte[] CA { get; set; } = []; // commissioner confirmation (32 bytes)

        public byte[] Encode()
        {
            var w = new TlvWriter();
            w.StartStructure(TlvTag.Anonymous).WriteBytes(TlvTag.ContextSpecific(1), CA).EndContainer();
            return w.ToArray();
        }

        public static Pake3 Decode(ReadOnlySpan<byte> tlv)
        {
            var msg = new Pake3();
            var r = new TlvReader(tlv);
            if (!r.Read() || !r.IsContainer) throw new FormatException("Pake3: expected a struct.");
            r.EnterContainer((ref TlvReader f) => { if (f.TagNumber == 1) msg.CA = f.GetBytes().ToArray(); });
            return msg;
        }
    }
}

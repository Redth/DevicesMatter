namespace MatterDevice.Core.Tlv;

/// <summary>
/// Matter TLV element type, the low 5 bits of a TLV control byte (Matter Core Spec, Appendix A.7.1).
/// Integers are little-endian on the wire.
/// </summary>
public enum TlvElementType : byte
{
    SignedInt1 = 0x00,
    SignedInt2 = 0x01,
    SignedInt4 = 0x02,
    SignedInt8 = 0x03,
    UnsignedInt1 = 0x04,
    UnsignedInt2 = 0x05,
    UnsignedInt4 = 0x06,
    UnsignedInt8 = 0x07,
    BooleanFalse = 0x08,
    BooleanTrue = 0x09,
    Float4 = 0x0A,
    Float8 = 0x0B,
    Utf8String1 = 0x0C,
    Utf8String2 = 0x0D,
    Utf8String4 = 0x0E,
    Utf8String8 = 0x0F,
    ByteString1 = 0x10,
    ByteString2 = 0x11,
    ByteString4 = 0x12,
    ByteString8 = 0x13,
    Null = 0x14,
    Structure = 0x15,
    Array = 0x16,
    List = 0x17,
    EndOfContainer = 0x18,
}

/// <summary>
/// TLV tag control, the high 3 bits of a TLV control byte (Matter Core Spec, Appendix A.7.2). Determines
/// how many tag bytes follow the control byte.
/// </summary>
public enum TlvTagControl : byte
{
    Anonymous = 0x00,        // 0 tag bytes
    ContextSpecific = 0x20,  // 1 tag byte
    CommonProfile2 = 0x40,   // 2 tag bytes
    CommonProfile4 = 0x60,   // 4 tag bytes
    ImplicitProfile2 = 0x80, // 2 tag bytes
    ImplicitProfile4 = 0xA0, // 4 tag bytes
    FullyQualified6 = 0xC0,  // 6 tag bytes (vendor 2 + profile 2 + tag 2)
    FullyQualified8 = 0xE0,  // 8 tag bytes (vendor 2 + profile 2 + tag 4)
}

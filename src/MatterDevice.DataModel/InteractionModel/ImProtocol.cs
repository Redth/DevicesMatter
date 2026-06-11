namespace MatterDevice.DataModel.InteractionModel;

/// <summary>
/// Interaction Model protocol opcodes (Protocol ID 0x0001). Values from
/// <c>connectedhomeip/src/protocols/interaction_model/Constants.h</c>.
/// </summary>
public enum ImOpcode : byte
{
    StatusResponse = 0x01,
    ReadRequest = 0x02,
    SubscribeRequest = 0x03,
    SubscribeResponse = 0x04,
    ReportData = 0x05,
    WriteRequest = 0x06,
    WriteResponse = 0x07,
    InvokeRequest = 0x08,
    InvokeResponse = 0x09,
    TimedRequest = 0x0A,
}

/// <summary>IM status codes (Matter Core Spec §8.10, "Status Code Table"). Subset.</summary>
public enum ImStatus : byte
{
    Success = 0x00,
    Failure = 0x01,
    InvalidAction = 0x80,
    UnsupportedEndpoint = 0x7F,
    UnsupportedCluster = 0xC3,
    UnsupportedAttribute = 0x86,
    UnsupportedCommand = 0x81,
    InvalidCommand = 0x85,
    UnsupportedWrite = 0x88,
    ConstraintError = 0x87,
}

/// <summary>The IM revision this implementation advertises (tag 0xFF on top-level IM messages).</summary>
public static class ImConstants
{
    public const byte InteractionModelRevision = 11;
    public const int InteractionModelRevisionTag = 0xFF;
}

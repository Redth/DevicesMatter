namespace MatterDevice.Core.Messaging;

/// <summary>Matter protocol IDs under the standard vendor (0x0000). Matter Core Spec §4.4.3.</summary>
public enum MatterProtocolId : ushort
{
    SecureChannel = 0x0000,
    InteractionModel = 0x0001,
    Bdx = 0x0002,
    UserDirectedCommissioning = 0x0003,
}

/// <summary>
/// Secure Channel protocol opcodes (Protocol ID 0x0000). Values from
/// <c>connectedhomeip/src/protocols/secure_channel/Constants.h</c>.
/// </summary>
public enum SecureChannelOpcode : byte
{
    MsgCounterSyncReq = 0x00,
    MsgCounterSyncRsp = 0x01,
    StandaloneAck = 0x10,
    PbkdfParamRequest = 0x20,
    PbkdfParamResponse = 0x21,
    PasePake1 = 0x22,
    PasePake2 = 0x23,
    PasePake3 = 0x24,
    CaseSigma1 = 0x30,
    CaseSigma2 = 0x31,
    CaseSigma3 = 0x32,
    CaseSigma2Resume = 0x33,
    StatusReport = 0x40,
}

/// <summary>General status codes used in a Secure Channel StatusReport. Matter Core Spec §4.13.2.4.</summary>
public enum GeneralStatusCode : ushort
{
    Success = 0x0000,
    Failure = 0x0001,
}

/// <summary>Secure Channel protocol-specific status codes for a StatusReport. §4.13.2.4 / Constants.h.</summary>
public enum SecureChannelStatusCode : ushort
{
    SessionEstablishmentSuccess = 0x0000,
    NoSharedTrustRoots = 0x0001,
    InvalidParameter = 0x0002,
    CloseSession = 0x0003,
    Busy = 0x0004,
    SessionNotFound = 0x0005,
}

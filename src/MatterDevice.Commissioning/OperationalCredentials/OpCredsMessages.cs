using MatterDevice.Core.Tlv;

namespace MatterDevice.Commissioning.OperationalCredentials;

/// <summary>
/// TLV codecs for the Node Operational Credentials cluster (0x003E) attestation/CSR payloads (Matter Core
/// Spec §11.17): the <c>attestation-elements</c> and <c>nocsr-elements</c> structures whose serialized
/// bytes are signed (with the DAC key) together with the session attestation challenge.
/// </summary>
public static class OpCredsMessages
{
    /// <summary>attestation-elements: { 1:certificationDeclaration, 2:attestationNonce, 3:timestamp }.</summary>
    public static byte[] EncodeAttestationElements(byte[] certificationDeclaration, byte[] attestationNonce, uint timestamp = 0)
    {
        var w = new TlvWriter();
        w.StartStructure(TlvTag.Anonymous)
            .WriteBytes(TlvTag.ContextSpecific(1), certificationDeclaration)
            .WriteBytes(TlvTag.ContextSpecific(2), attestationNonce)
            .WriteUInt(TlvTag.ContextSpecific(3), timestamp)
            .EndContainer();
        return w.ToArray();
    }

    public sealed record AttestationElements(byte[] CertificationDeclaration, byte[] AttestationNonce, uint Timestamp);

    public static AttestationElements DecodeAttestationElements(ReadOnlySpan<byte> tlv)
    {
        byte[] cd = [], nonce = [];
        uint ts = 0;
        var r = new TlvReader(tlv);
        if (!r.Read() || !r.IsContainer) throw new FormatException("attestation-elements: expected a struct.");
        r.EnterContainer((ref TlvReader f) =>
        {
            switch (f.TagNumber)
            {
                case 1: cd = f.GetBytes().ToArray(); break;
                case 2: nonce = f.GetBytes().ToArray(); break;
                case 3: ts = (uint)f.GetUInt(); break;
            }
        });
        return new AttestationElements(cd, nonce, ts);
    }

    /// <summary>nocsr-elements: { 1:csr (PKCS#10 DER), 2:csrNonce }.</summary>
    public static byte[] EncodeNocsrElements(byte[] csrDer, byte[] csrNonce)
    {
        var w = new TlvWriter();
        w.StartStructure(TlvTag.Anonymous)
            .WriteBytes(TlvTag.ContextSpecific(1), csrDer)
            .WriteBytes(TlvTag.ContextSpecific(2), csrNonce)
            .EndContainer();
        return w.ToArray();
    }

    public sealed record NocsrElements(byte[] Csr, byte[] CsrNonce);

    public static NocsrElements DecodeNocsrElements(ReadOnlySpan<byte> tlv)
    {
        byte[] csr = [], nonce = [];
        var r = new TlvReader(tlv);
        if (!r.Read() || !r.IsContainer) throw new FormatException("nocsr-elements: expected a struct.");
        r.EnterContainer((ref TlvReader f) =>
        {
            switch (f.TagNumber)
            {
                case 1: csr = f.GetBytes().ToArray(); break;
                case 2: nonce = f.GetBytes().ToArray(); break;
            }
        });
        return new NocsrElements(csr, nonce);
    }
}

/// <summary>Node Operational Cert status (NOCResponse StatusCode, Matter Core Spec §11.17.5.2).</summary>
public enum NodeOperationalCertStatus : byte
{
    Ok = 0,
    InvalidPublicKey = 1,
    InvalidNodeOpId = 2,
    InvalidNoc = 3,
    MissingCsr = 4,
    TableFull = 5,
    InvalidAdminSubject = 6,
    FabricConflict = 9,
    LabelConflict = 10,
    InvalidFabricIndex = 11,
}

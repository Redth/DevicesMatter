using MatterDevice.Core.Tlv;

namespace MatterDevice.Core.Credentials;

/// <summary>
/// The standard Matter certificate extensions (Matter Core Spec §6.5.11): basic-constraints, key-usage,
/// subject/authority key identifiers. Encoded as a TLV <b>List</b> with context tags 1–6.
/// </summary>
public sealed class CertificateExtensions
{
    private const int TagBasicConstraints = 1;
    private const int TagKeyUsage = 2;
    private const int TagExtendedKeyUsage = 3;
    private const int TagSubjectKeyId = 4;
    private const int TagAuthorityKeyId = 5;

    // basic-constraints sub-tags
    private const int TagIsCa = 1;
    private const int TagPathLen = 2;

    public bool IsCa { get; set; }
    public uint? PathLengthConstraint { get; set; }
    public ushort KeyUsage { get; set; }
    public IReadOnlyList<uint> ExtendedKeyUsage { get; set; } = [];
    public byte[]? SubjectKeyId { get; set; }      // 20 bytes
    public byte[]? AuthorityKeyId { get; set; }    // 20 bytes

    public void Write(TlvWriter w, TlvTag tag)
    {
        w.StartList(tag);

        // basic-constraints (always present)
        w.StartStructure(TlvTag.ContextSpecific(TagBasicConstraints));
        w.WriteBool(TlvTag.ContextSpecific(TagIsCa), IsCa);
        if (PathLengthConstraint is { } pl)
            w.WriteUInt(TlvTag.ContextSpecific(TagPathLen), pl);
        w.EndContainer();

        w.WriteUInt(TlvTag.ContextSpecific(TagKeyUsage), KeyUsage);

        if (SubjectKeyId is { } skid)
            w.WriteBytes(TlvTag.ContextSpecific(TagSubjectKeyId), skid);
        if (AuthorityKeyId is { } akid)
            w.WriteBytes(TlvTag.ContextSpecific(TagAuthorityKeyId), akid);

        w.EndContainer();
    }

    public static CertificateExtensions Read(ref TlvReader list)
    {
        var ext = new CertificateExtensions();
        list.EnterContainer((ref TlvReader f) =>
        {
            switch (f.TagNumber)
            {
                case TagBasicConstraints when f.IsContainer:
                    var captured = (IsCa: false, PathLen: (uint?)null);
                    f.EnterContainer((ref TlvReader g) =>
                    {
                        switch (g.TagNumber)
                        {
                            case TagIsCa: captured.IsCa = g.GetBool(); break;
                            case TagPathLen: captured.PathLen = (uint)g.GetUInt(); break;
                        }
                    });
                    ext.IsCa = captured.IsCa;
                    ext.PathLengthConstraint = captured.PathLen;
                    break;
                case TagKeyUsage: ext.KeyUsage = (ushort)f.GetUInt(); break;
                case TagExtendedKeyUsage when f.IsContainer:
                    var ekus = new List<uint>();
                    f.EnterContainer((ref TlvReader e) => ekus.Add((uint)e.GetUInt()));
                    ext.ExtendedKeyUsage = ekus;
                    break;
                case TagSubjectKeyId: ext.SubjectKeyId = f.GetBytes().ToArray(); break;
                case TagAuthorityKeyId: ext.AuthorityKeyId = f.GetBytes().ToArray(); break;
            }
        });
        return ext;
    }
}

/// <summary>X.509 KeyUsage bit flags (RFC 5280) as used by Matter certs.</summary>
[Flags]
public enum MatterKeyUsage : ushort
{
    DigitalSignature = 0x0001, // NOC leaf
    KeyCertSign = 0x0020,      // CA certs
    CrlSign = 0x0040,          // CA certs
}

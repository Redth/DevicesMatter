using MatterDevice.Core.Tlv;

namespace MatterDevice.Core.Credentials;

/// <summary>
/// A Matter operational certificate in its TLV encoding (Matter Core Spec §6.5.2) — RCAC, ICAC, or NOC.
/// Carries the operational public key, the issuer/subject distinguished names, validity, the standard
/// extensions, and the raw 64-byte ECDSA signature.
/// </summary>
/// <remarks>
/// The certificate <em>structure</em> and tags are spec-exact. The signature (tag 11) is computed over
/// the certificate's to-be-signed TLV bytes (tags 1–10) by <see cref="OperationalCredentials"/>; for full
/// chip-tool interop the signature domain is the X.509 DER TBSCertificate (a mechanical TLV↔DER
/// conversion) — see <c>docs/01-milestone1-progress.md</c>.
/// </remarks>
public sealed class MatterCertificate
{
    private const int TagSerialNumber = 1;
    private const int TagSignatureAlgorithm = 2;
    private const int TagIssuer = 3;
    private const int TagNotBefore = 4;
    private const int TagNotAfter = 5;
    private const int TagSubject = 6;
    private const int TagPublicKeyAlgorithm = 7;
    private const int TagEllipticCurveId = 8;
    private const int TagEllipticCurvePublicKey = 9;
    private const int TagExtensions = 10;
    private const int TagSignature = 11;

    public byte[] SerialNumber { get; set; } = [];
    public uint SignatureAlgorithm { get; set; } = 1; // ecdsa-with-sha256
    public required MatterDistinguishedName Issuer { get; set; }
    public uint NotBefore { get; set; }
    public uint NotAfter { get; set; }
    public required MatterDistinguishedName Subject { get; set; }
    public uint PublicKeyAlgorithm { get; set; } = 1; // ec-pub-key
    public uint EllipticCurveId { get; set; } = 1;     // prime256v1
    public required byte[] EllipticCurvePublicKey { get; set; } // 65-byte uncompressed point
    public CertificateExtensions Extensions { get; set; } = new();
    public byte[] Signature { get; set; } = [];

    /// <summary>Serializes the full certificate (including the signature) to TLV.</summary>
    public byte[] Encode()
    {
        var w = new TlvWriter();
        WriteToBeSigned(w, includeSignature: true);
        return w.ToArray();
    }

    /// <summary>The to-be-signed bytes — the certificate structure with the signature element omitted.</summary>
    public byte[] EncodeToBeSigned()
    {
        var w = new TlvWriter();
        WriteToBeSigned(w, includeSignature: false);
        return w.ToArray();
    }

    private void WriteToBeSigned(TlvWriter w, bool includeSignature)
    {
        w.StartStructure(TlvTag.Anonymous);
        w.WriteBytes(TlvTag.ContextSpecific(TagSerialNumber), SerialNumber);
        w.WriteUInt(TlvTag.ContextSpecific(TagSignatureAlgorithm), SignatureAlgorithm);
        Issuer.Write(w, TlvTag.ContextSpecific(TagIssuer));
        w.WriteUInt(TlvTag.ContextSpecific(TagNotBefore), NotBefore);
        w.WriteUInt(TlvTag.ContextSpecific(TagNotAfter), NotAfter);
        Subject.Write(w, TlvTag.ContextSpecific(TagSubject));
        w.WriteUInt(TlvTag.ContextSpecific(TagPublicKeyAlgorithm), PublicKeyAlgorithm);
        w.WriteUInt(TlvTag.ContextSpecific(TagEllipticCurveId), EllipticCurveId);
        w.WriteBytes(TlvTag.ContextSpecific(TagEllipticCurvePublicKey), EllipticCurvePublicKey);
        Extensions.Write(w, TlvTag.ContextSpecific(TagExtensions));
        if (includeSignature)
            w.WriteBytes(TlvTag.ContextSpecific(TagSignature), Signature);
        w.EndContainer();
    }

    public static MatterCertificate Decode(ReadOnlySpan<byte> tlv)
    {
        MatterDistinguishedName? issuer = null, subject = null;
        var cert = new MatterCertificate
        {
            Issuer = new MatterDistinguishedName(),
            Subject = new MatterDistinguishedName(),
            EllipticCurvePublicKey = [],
        };

        var r = new TlvReader(tlv);
        if (!r.Read() || !r.IsContainer) throw new FormatException("Certificate: expected a struct.");
        r.EnterContainer((ref TlvReader f) =>
        {
            switch (f.TagNumber)
            {
                case TagSerialNumber: cert.SerialNumber = f.GetBytes().ToArray(); break;
                case TagSignatureAlgorithm: cert.SignatureAlgorithm = (uint)f.GetUInt(); break;
                case TagIssuer when f.IsContainer: issuer = MatterDistinguishedName.Read(ref f); break;
                case TagNotBefore: cert.NotBefore = (uint)f.GetUInt(); break;
                case TagNotAfter: cert.NotAfter = (uint)f.GetUInt(); break;
                case TagSubject when f.IsContainer: subject = MatterDistinguishedName.Read(ref f); break;
                case TagPublicKeyAlgorithm: cert.PublicKeyAlgorithm = (uint)f.GetUInt(); break;
                case TagEllipticCurveId: cert.EllipticCurveId = (uint)f.GetUInt(); break;
                case TagEllipticCurvePublicKey: cert.EllipticCurvePublicKey = f.GetBytes().ToArray(); break;
                case TagExtensions when f.IsContainer: cert.Extensions = CertificateExtensions.Read(ref f); break;
                case TagSignature: cert.Signature = f.GetBytes().ToArray(); break;
            }
        });

        if (issuer is not null) cert.Issuer = issuer;
        if (subject is not null) cert.Subject = subject;
        return cert;
    }
}

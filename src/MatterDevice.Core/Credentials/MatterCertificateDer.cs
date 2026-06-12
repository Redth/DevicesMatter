using System.Formats.Asn1;
using MatterDevice.Core.Crypto;

namespace MatterDevice.Core.Credentials;

/// <summary>
/// Converts a Matter-TLV operational certificate to its X.509 DER <c>TBSCertificate</c> (Matter Core Spec
/// §6.5.1, "Conversion to X.509"), so a certificate's signature — which is computed over the DER TBS, not
/// the TLV — can be verified the way every other Matter implementation (chip-tool, matter.js) does.
/// </summary>
public static class MatterCertificateDer
{
    // Algorithm / curve OIDs.
    private const string EcdsaWithSha256 = "1.2.840.10045.4.3.2";
    private const string IdEcPublicKey = "1.2.840.10045.2.1";
    private const string Prime256v1 = "1.2.840.10045.3.1.7";

    // X.509 extension OIDs.
    private const string OidBasicConstraints = "2.5.29.19";
    private const string OidKeyUsage = "2.5.29.15";
    private const string OidExtKeyUsage = "2.5.29.37";
    private const string OidSubjectKeyId = "2.5.29.14";
    private const string OidAuthorityKeyId = "2.5.29.35";

    // Extended key usage purpose OIDs (Matter uses serverAuth + clientAuth on NOCs).
    private static readonly string[] EkuOids =
        ["", "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.3", "1.3.6.1.5.5.7.3.4", "1.3.6.1.5.5.7.3.8", "1.3.6.1.5.5.7.3.9"];

    private static readonly DateTimeOffset MatterEpoch = new(2000, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>Verifies <paramref name="cert"/>'s signature against an issuer public key, over the DER TBSCertificate.</summary>
    public static bool VerifySignature(MatterCertificate cert, ReadOnlySpan<byte> issuerPublicKey)
    {
        byte[] tbs;
        try { tbs = EncodeTbsCertificate(cert); }
        catch { return false; }
        return P256.Verify(issuerPublicKey, tbs, cert.Signature);
    }

    /// <summary>Builds the DER-encoded TBSCertificate for a Matter certificate.</summary>
    public static byte[] EncodeTbsCertificate(MatterCertificate cert)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            // version [0] EXPLICIT INTEGER v3(2)
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                w.WriteInteger(2);

            // serialNumber INTEGER (from the octet string, as a positive integer)
            w.WriteInteger(SerialInteger(cert.SerialNumber));

            // signature AlgorithmIdentifier (ecdsa-with-SHA256)
            using (w.PushSequence())
                w.WriteObjectIdentifier(EcdsaWithSha256);

            WriteName(w, cert.Issuer);
            WriteValidity(w, cert.NotBefore, cert.NotAfter);
            WriteName(w, cert.Subject);
            WriteSpki(w, cert.EllipticCurvePublicKey);
            WriteExtensions(w, cert.Extensions);
        }
        return w.Encode();
    }

    // ---- Name (issuer/subject) ------------------------------------------

    private static void WriteName(AsnWriter w, MatterDistinguishedName dn)
    {
        // Name ::= SEQUENCE OF RelativeDistinguishedName; each RDN is a SET OF AttributeTypeAndValue.
        using var _ = w.PushSequence();
        foreach (var (type, intValue, stringValue) in dn.Attributes)
        {
            using var set = w.PushSetOf();
            using var atv = w.PushSequence();
            w.WriteObjectIdentifier(DnAttributeOid(type));
            if (stringValue is not null)
                w.WriteCharacterString(UniversalTagNumber.UTF8String, stringValue);
            else
                // Matter id attributes render as a fixed-width uppercase-hex UTF8String.
                w.WriteCharacterString(UniversalTagNumber.UTF8String, MatterIdHex(type, intValue));
        }
    }

    private static string MatterIdHex(DnAttributeType type, ulong value) =>
        type == DnAttributeType.MatterCaseAuthTag ? value.ToString("X8") : value.ToString("X16");

    private static string DnAttributeOid(DnAttributeType type) => type switch
    {
        DnAttributeType.CommonName => "2.5.4.3",
        DnAttributeType.MatterNodeId => "1.3.6.1.4.1.37244.1.1",
        DnAttributeType.MatterFirmwareSigningId => "1.3.6.1.4.1.37244.1.2",
        DnAttributeType.MatterIcacId => "1.3.6.1.4.1.37244.1.3",
        DnAttributeType.MatterRcacId => "1.3.6.1.4.1.37244.1.4",
        DnAttributeType.MatterFabricId => "1.3.6.1.4.1.37244.1.5",
        DnAttributeType.MatterCaseAuthTag => "1.3.6.1.4.1.37244.1.6",
        _ => throw new NotSupportedException($"DN attribute {type}"),
    };

    // ---- Validity -------------------------------------------------------

    private static void WriteValidity(AsnWriter w, uint notBefore, uint notAfter)
    {
        using var _ = w.PushSequence();
        WriteTime(w, notBefore, isNotAfter: false);
        WriteTime(w, notAfter, isNotAfter: true);
    }

    private static void WriteTime(AsnWriter w, uint matterSeconds, bool isNotAfter)
    {
        if (matterSeconds == 0 && isNotAfter)
        {
            // "no well-defined expiry" → 99991231235959Z (GeneralizedTime).
            w.WriteGeneralizedTime(new DateTimeOffset(9999, 12, 31, 23, 59, 59, TimeSpan.Zero));
            return;
        }
        var time = MatterEpoch.AddSeconds(matterSeconds);
        if (time.Year is >= 1950 and <= 2049)
            w.WriteUtcTime(time, twoDigitYearMax: 2049);
        else
            w.WriteGeneralizedTime(time);
    }

    // ---- SubjectPublicKeyInfo -------------------------------------------

    private static void WriteSpki(AsnWriter w, byte[] publicKey)
    {
        using var _ = w.PushSequence();
        using (w.PushSequence())
        {
            w.WriteObjectIdentifier(IdEcPublicKey);
            w.WriteObjectIdentifier(Prime256v1);
        }
        w.WriteBitString(publicKey);
    }

    // ---- Extensions [3] -------------------------------------------------

    private static void WriteExtensions(AsnWriter w, CertificateExtensions ext)
    {
        using var explicitTag = w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true));
        using var seq = w.PushSequence();

        // basicConstraints (critical)
        WriteExtension(w, OidBasicConstraints, critical: true, inner =>
        {
            using var _ = inner.PushSequence();
            if (ext.IsCa)
            {
                inner.WriteBoolean(true);
                if (ext.PathLengthConstraint is { } pl)
                    inner.WriteInteger(pl);
            }
        });

        // keyUsage (critical)
        WriteExtension(w, OidKeyUsage, critical: true, inner =>
            inner.WriteBitString(KeyUsageBits(ext.KeyUsage, out var unused), unusedBitCount: unused));

        // extendedKeyUsage (critical, per Matter spec) — present on NOCs
        if (ext.ExtendedKeyUsage.Count > 0)
        {
            WriteExtension(w, OidExtKeyUsage, critical: true, inner =>
            {
                using var _ = inner.PushSequence();
                foreach (var eku in ext.ExtendedKeyUsage)
                    inner.WriteObjectIdentifier(EkuOids[eku]);
            });
        }

        // subjectKeyIdentifier
        if (ext.SubjectKeyId is { } skid)
            WriteExtension(w, OidSubjectKeyId, critical: false, inner => inner.WriteOctetString(skid));

        // authorityKeyIdentifier
        if (ext.AuthorityKeyId is { } akid)
        {
            WriteExtension(w, OidAuthorityKeyId, critical: false, inner =>
            {
                using var _ = inner.PushSequence();
                inner.WriteOctetString(akid, new Asn1Tag(TagClass.ContextSpecific, 0)); // keyIdentifier [0]
            });
        }
    }

    private static void WriteExtension(AsnWriter w, string oid, bool critical, Action<AsnWriter> writeValue)
    {
        using var _ = w.PushSequence();
        w.WriteObjectIdentifier(oid);
        if (critical)
            w.WriteBoolean(true);

        // extnValue is an OCTET STRING wrapping the DER of the extension value.
        var inner = new AsnWriter(AsnEncodingRules.DER);
        writeValue(inner);
        w.WriteOctetString(inner.Encode());
    }

    // ---- helpers --------------------------------------------------------

    /// <summary>Converts a Matter KeyUsage bitmap to the DER BIT STRING bytes + unused-bit count.</summary>
    private static byte[] KeyUsageBits(ushort keyUsage, out int unusedBits)
    {
        // Matter stores bit n at value (1 << n); X.509 BIT STRING puts bit 0 in the MSB.
        var reversed = 0;
        var highest = -1;
        for (var n = 0; n < 16; n++)
        {
            if ((keyUsage & (1 << n)) != 0)
            {
                reversed |= 1 << (15 - n);
                highest = n;
            }
        }
        // emit the minimum number of bytes covering the highest set bit
        if (highest < 0) { unusedBits = 0; return [0]; }
        var totalBits = highest + 1;
        var byteCount = (totalBits + 7) / 8;
        unusedBits = byteCount * 8 - totalBits;
        var bytes = new byte[byteCount];
        for (var i = 0; i < byteCount; i++)
            bytes[i] = (byte)(reversed >> (8 * (1 - i)) & 0xFF);
        return bytes;
    }

    private static System.Numerics.BigInteger SerialInteger(byte[] serial)
    {
        if (serial.Length == 0)
            return System.Numerics.BigInteger.Zero;
        // big-endian, unsigned
        return new System.Numerics.BigInteger(serial, isUnsigned: true, isBigEndian: true);
    }
}

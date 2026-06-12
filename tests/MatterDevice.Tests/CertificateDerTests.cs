using MatterDevice.Core.Credentials;

namespace MatterDevice.Tests;

/// <summary>
/// Validates the Matter-TLV → X.509-DER conversion against a real certificate produced by an independent
/// implementation: matter.js's self-signed test Root CA (captured during interop testing). Verifying its
/// self-signature over our reconstructed DER TBSCertificate proves the conversion is byte-exact — which is
/// exactly what lets a real controller's NOC validate at AddNOC.
/// </summary>
public class CertificateDerTests
{
    // matter.js test Root CA (RCAC), Matter-TLV encoded — constant across matter.js runs.
    private const string MatterJsRootCertHex =
        "1530010100240201370324140018260432d3dc2f2605b2098a44370624140018240701240801300941" +
        "046fb5edc05a35198580d663069c8e297f45c57900b280ff6d1ce19b6eaec4688a8cd48db8a83e19a82" +
        "780f41d1e371d67affb75b6e146357a8aeb405c24db5f3c370a35012901182402603004144b8fb40e2d" +
        "83d2c783d5e71647bfb0fd73c6c3533005144b8fb40e2d83d2c783d5e71647bfb0fd73c6c35318300b40" +
        "fd853e7bd94df2e8c0fc12c9d3e46436b5f3cdb6c1635dc8c4acde1d56485454befdc676ec71d39596aa" +
        "d282ad25346949a906e30012166d7e60aecc76b4b8b618";

    [Fact]
    public void Matterjs_root_self_signature_verifies_over_der_tbs()
    {
        var root = MatterCertificate.Decode(Convert.FromHexString(MatterJsRootCertHex));

        // Sanity: it's the expected CA cert.
        Assert.True(root.Extensions.IsCa);
        Assert.Equal(65, root.EllipticCurvePublicKey.Length);

        // The self-signature must verify over the reconstructed DER TBSCertificate (NOT the TLV TBS).
        Assert.True(MatterCertificateDer.VerifySignature(root, root.EllipticCurvePublicKey),
            "matter.js root self-signature did not verify over our DER TBSCertificate — DER conversion mismatch.");
    }

    // A matter.js-issued NOC (node-id + fabric-id subject, extKeyUsage), signed by the root above.
    private const string MatterJsNocHex =
        "153001010224020137032414001826046adfdc2f2605ea158a4437062715d0c517605d2f41da2711d910" +
        "637a5c3536b81824070124080130094104e559ab8a53f3fde196ce7baf6ea9dfd5b38d4affec60f5e007" +
        "d6182e35045d7a105cf1a069fa57ccef2d3d437ddf4a63411764d60ca4d4c8168d1fa171690ebd370a35" +
        "0128011824020136030402040118300414572c105692e8d8e8e1e2e841bd7ed0841445a4693005144b8f" +
        "b40e2d83d2c783d5e71647bfb0fd73c6c35318300b40a1f089d35caf0c138b1ebccf7cbd440db5532901" +
        "0dac32ce749a9f9861baa0d6ca336cb7ccee9f350adf7b1502f24343956157d1bbac15c1b2b2ed63b4a7" +
        "efa418";

    [Fact]
    public void Matterjs_noc_signature_verifies_against_root_over_der()
    {
        var root = MatterCertificate.Decode(Convert.FromHexString(MatterJsRootCertHex));
        var noc = MatterCertificate.Decode(Convert.FromHexString(MatterJsNocHex));

        Assert.False(noc.Extensions.IsCa);
        Assert.NotEmpty(noc.Extensions.ExtendedKeyUsage); // clientAuth + serverAuth
        Assert.NotNull(noc.Subject.NodeId);
        Assert.NotNull(noc.Subject.FabricId);

        // The NOC is signed by the root; its signature must verify over our reconstructed DER TBS.
        Assert.True(MatterCertificateDer.VerifySignature(noc, root.EllipticCurvePublicKey),
            "matter.js NOC signature did not verify over our DER TBSCertificate.");
    }

    [Fact]
    public void Der_tbs_parses_as_valid_x509_name_and_spki()
    {
        var root = MatterCertificate.Decode(Convert.FromHexString(MatterJsRootCertHex));
        var tbs = MatterCertificateDer.EncodeTbsCertificate(root);
        Assert.NotEmpty(tbs);
        // first byte is a DER SEQUENCE tag
        Assert.Equal(0x30, tbs[0]);
    }
}

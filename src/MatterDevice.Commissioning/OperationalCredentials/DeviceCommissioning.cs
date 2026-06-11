using MatterDevice.Core.Credentials;
using MatterDevice.Core.Crypto;
using CoreOpCreds = MatterDevice.Core.Credentials.OperationalCredentials;

namespace MatterDevice.Commissioning.OperationalCredentials;

/// <summary>An AttestationResponse: the signed attestation elements.</summary>
public sealed record AttestationResult(byte[] AttestationElements, byte[] Signature);

/// <summary>A CSRResponse: the signed NOCSR elements (carrying the device's operational CSR).</summary>
public sealed record CsrResult(byte[] NocsrElements, byte[] Signature);

/// <summary>
/// The device side of the operational-credentials commissioning flow (Matter Core Spec §11.17), running
/// inside the PASE session: prove attestation, emit a CSR for a freshly-generated operational key, then
/// install the trusted root + NOC the commissioner returns — producing a <see cref="Fabric"/> that CASE
/// can use. Drive it: <see cref="HandleAttestationRequest"/> → <see cref="HandleCsrRequest"/> →
/// <see cref="HandleAddTrustedRoot"/> → <see cref="HandleAddNoc"/>.
/// </summary>
public sealed class DeviceCommissioning(DeviceAttestationProvider attestation, FabricTable fabrics)
{
    private readonly DeviceAttestationProvider _attestation = attestation;
    private readonly FabricTable _fabrics = fabrics;

    private P256KeyPair? _operationalKey;       // generated for the CSR, kept to pair with the NOC
    private MatterCertificate? _pendingRoot;    // from AddTrustedRootCertificate, applied at AddNOC

    /// <summary>AttestationRequest: returns attestation elements signed (with the DAC) over elements ‖ challenge.</summary>
    public AttestationResult HandleAttestationRequest(byte[] attestationNonce, ReadOnlySpan<byte> attestationChallenge)
    {
        var elements = OpCredsMessages.EncodeAttestationElements(_attestation.CertificationDeclaration, attestationNonce);
        var signature = _attestation.SignWithDac(elements, attestationChallenge);
        return new AttestationResult(elements, signature);
    }

    /// <summary>The DAC / PAI certificate (X.509 DER) for CertificateChainRequest (1 = DAC, 2 = PAI).</summary>
    public byte[] HandleCertificateChainRequest(int certificateType) => certificateType switch
    {
        1 => _attestation.DacCertificateDer,
        2 => _attestation.PaiCertificateDer,
        _ => throw new ArgumentOutOfRangeException(nameof(certificateType)),
    };

    /// <summary>CSRRequest: generates the operational key pair and returns a DAC-signed NOCSR (CSR + nonce).</summary>
    public CsrResult HandleCsrRequest(byte[] csrNonce, ReadOnlySpan<byte> attestationChallenge)
    {
        _operationalKey = P256KeyPair.Generate();
        var csrDer = _operationalKey.CreateCsr();
        var elements = OpCredsMessages.EncodeNocsrElements(csrDer, csrNonce);
        var signature = _attestation.SignWithDac(elements, attestationChallenge);
        return new CsrResult(elements, signature);
    }

    /// <summary>AddTrustedRootCertificate: stores the fabric root (applied when AddNOC arrives).</summary>
    public void HandleAddTrustedRoot(byte[] rootCertificateTlv) =>
        _pendingRoot = MatterCertificate.Decode(rootCertificateTlv);

    /// <summary>
    /// AddNOC: installs the NOC + IPK, derives the device's node/fabric ids from the NOC subject, and
    /// commits a <see cref="Fabric"/>. Returns the NOC status and (on success) the new fabric index.
    /// </summary>
    public (NodeOperationalCertStatus Status, byte? FabricIndex) HandleAddNoc(byte[] nocTlv, byte[] ipkValue)
    {
        if (_operationalKey is null) return (NodeOperationalCertStatus.MissingCsr, null);
        if (_pendingRoot is null) return (NodeOperationalCertStatus.InvalidNoc, null);
        if (ipkValue.Length != 16) return (NodeOperationalCertStatus.InvalidPublicKey, null);

        var noc = MatterCertificate.Decode(nocTlv);

        // The NOC's public key must be the one we generated for the CSR.
        if (!noc.EllipticCurvePublicKey.AsSpan().SequenceEqual(_operationalKey.PublicKey))
            return (NodeOperationalCertStatus.InvalidPublicKey, null);

        var fabricId = noc.Subject.FabricId;
        var nodeId = noc.Subject.NodeId;
        if (fabricId is null || nodeId is null) return (NodeOperationalCertStatus.InvalidNodeOpId, null);

        if (!CoreOpCreds.ValidateChain(noc, _pendingRoot, fabricId.Value))
            return (NodeOperationalCertStatus.InvalidNoc, null);

        var index = _fabrics.Add(i => new Fabric
        {
            FabricIndex = i,
            FabricId = fabricId.Value,
            NodeId = nodeId.Value,
            RootCertificate = _pendingRoot,
            Noc = noc,
            OperationalKey = _operationalKey,
            EpochIpk = ipkValue,
        });
        return (NodeOperationalCertStatus.Ok, index);
    }
}

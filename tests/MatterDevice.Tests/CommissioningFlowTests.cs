using System.Security.Cryptography;
using MatterDevice.Commissioning.Case;
using MatterDevice.Commissioning.OperationalCredentials;
using MatterDevice.Commissioning.Pase;
using MatterDevice.Core.Credentials;
using MatterDevice.Core.Crypto;

namespace MatterDevice.Tests;

/// <summary>
/// The whole commission-to-operational journey in one test, exercising every layer in sequence the way a
/// real controller does:
/// <list type="number">
/// <item>PASE establishes a session and an attestation challenge,</item>
/// <item>the device proves attestation (DAC-signed) and emits a CSR for a fresh operational key,</item>
/// <item>the commissioner installs the trusted root + a NOC, committing a fabric, and</item>
/// <item>CASE then establishes an operational session on that very fabric, with both sides agreeing on keys.</item>
/// </list>
/// This is the end-to-end proof that the device side can be commissioned and brought to operational.
/// </summary>
public class CommissioningFlowTests
{
    private const uint Passcode = 20202021;
    private const ulong FabricId = 0xFAB000000000001D;
    private const ulong DeviceNodeId = 0x00000000DEDEDEDE;
    private const ulong CommissionerNodeId = 0x000000001234ABCD;
    private const ulong RcacId = 0xCACACACA00000001;

    [Fact]
    public void Device_commissions_to_operational_pase_attestation_csr_addnoc_then_case()
    {
        // ---------- 1. PASE: session + attestation challenge ----------
        var salt = RandomNumberGenerator.GetBytes(16);
        var pase = new PaseResponder(Passcode, salt, 1000, 0x0001);
        var paseProver = new TestProver(Passcode);

        var req = paseProver.BuildPbkdfParamRequest();
        var resp = pase.OnPbkdfParamRequest(req).Encode();
        paseProver.OnPbkdfParamResponse(req, resp);
        var pake2 = pase.OnPake1(paseProver.BuildPake1());
        var paseSession = pase.OnPake3(paseProver.OnPake2BuildPake3(pake2.Encode()));
        Assert.NotNull(paseSession);

        var deviceChallenge = paseSession!.AttestationChallenge;
        var commissionerChallenge = paseProver.SessionKeys!.Value.Attest;
        Assert.Equal(Convert.ToHexString(deviceChallenge), Convert.ToHexString(commissionerChallenge)); // same challenge

        // ---------- device-side commissioning state ----------
        var dacKey = P256KeyPair.Generate();
        var attestation = new DeviceAttestationProvider(
            dacKey,
            dacCertificateDer: RandomNumberGenerator.GetBytes(64),  // stand-in for the CHIP test DAC X.509
            paiCertificateDer: RandomNumberGenerator.GetBytes(64),
            certificationDeclaration: RandomNumberGenerator.GetBytes(128));
        var fabrics = new FabricTable();
        var commissioning = new DeviceCommissioning(attestation, fabrics);

        // ---------- 2. Attestation ----------
        var attNonce = RandomNumberGenerator.GetBytes(32);
        var attestationResult = commissioning.HandleAttestationRequest(attNonce, deviceChallenge);
        Assert.True(DeviceAttestationProvider.VerifyDacSignature(
            dacKey.PublicKey, attestationResult.AttestationElements, commissionerChallenge, attestationResult.Signature));
        // the nonce echoes back
        Assert.Equal(Convert.ToHexString(attNonce),
            Convert.ToHexString(OpCredsMessages.DecodeAttestationElements(attestationResult.AttestationElements).AttestationNonce));

        // ---------- 3. CSR ----------
        var csrNonce = RandomNumberGenerator.GetBytes(32);
        var csrResult = commissioning.HandleCsrRequest(csrNonce, deviceChallenge);
        Assert.True(DeviceAttestationProvider.VerifyDacSignature(
            dacKey.PublicKey, csrResult.NocsrElements, commissionerChallenge, csrResult.Signature));
        var nocsr = OpCredsMessages.DecodeNocsrElements(csrResult.NocsrElements);
        var operationalPublicKey = P256KeyPair.PublicKeyFromCsr(nocsr.Csr); // commissioner extracts the op pubkey

        // ---------- commissioner builds the fabric credentials ----------
        var rootKey = P256KeyPair.Generate();
        var root = OperationalCredentials.CreateRootCertificate(rootKey, RcacId);
        var deviceNoc = OperationalCredentials.CreateNodeCertificate(rootKey, root, operationalPublicKey, FabricId, DeviceNodeId);
        var ipk = RandomNumberGenerator.GetBytes(16);

        // ---------- 4. AddTrustedRoot + AddNOC ----------
        commissioning.HandleAddTrustedRoot(root.Encode());
        var (status, fabricIndex) = commissioning.HandleAddNoc(deviceNoc.Encode(), ipk);
        Assert.Equal(NodeOperationalCertStatus.Ok, status);
        Assert.NotNull(fabricIndex);
        Assert.Equal(1, fabrics.Count);

        // ---------- 5. CASE on the freshly-commissioned fabric ----------
        var device = new CaseResponder(fabrics, localSessionId: 0xA1A1);

        var commissionerKey = P256KeyPair.Generate();
        var commissionerNoc = OperationalCredentials.CreateNodeCertificate(rootKey, root, commissionerKey, FabricId, CommissionerNodeId);
        var caseInitiator = new CaseInitiator(root, ipk, FabricId, DeviceNodeId, commissionerNoc, commissionerKey, 0xB2B2);

        var sigma1 = caseInitiator.BuildSigma1();
        var sigma2 = device.OnSigma1(sigma1).Encode();
        var sigma3 = caseInitiator.OnSigma2BuildSigma3(sigma2);
        var operationalSession = device.OnSigma3(sigma3);

        Assert.NotNull(operationalSession);
        Assert.Equal(SessionOriginCase, operationalSession!.Origin.ToString());
        Assert.Equal(Convert.ToHexString(caseInitiator.SessionKeys!.Value.I2R), Convert.ToHexString(operationalSession.DecryptKey));
        Assert.Equal(Convert.ToHexString(caseInitiator.SessionKeys.Value.R2I), Convert.ToHexString(operationalSession.EncryptKey));
        Assert.Equal(CommissionerNodeId, operationalSession.PeerNodeId);
    }

    private const string SessionOriginCase = "Case";
}

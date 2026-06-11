using System.Text;
using MatterDevice.Core.Crypto;

namespace MatterDevice.Tests;

/// <summary>
/// Validates the SPAKE2+ implementation byte-for-byte against the canonical CHIP/RFC test vector
/// (<c>connectedhomeip/src/crypto/tests/SPAKE2P_RFC_test_vectors.h</c>, vector 1, context
/// <c>"SPAKE2+-P256-SHA256-HKDF draft-01"</c>). Reproducing X, Y, Z, V, Ka, Ke, KcA and KcB from the
/// vector's w0/w1/x/y proves the curve math, transcript construction and key schedule are correct —
/// this is the single biggest interop risk for PASE, so it is pinned by a known-answer test.
/// </summary>
public class Spake2PlusKnownAnswerTests
{
    // Vector 1 (verbatim from the CHIP header).
    private static readonly byte[] Context = Encoding.ASCII.GetBytes("SPAKE2+-P256-SHA256-HKDF draft-01");
    private static readonly byte[] ProverId = Encoding.ASCII.GetBytes("client");
    private static readonly byte[] VerifierId = Encoding.ASCII.GetBytes("server");

    private static readonly byte[] W0 = H("e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c");
    private static readonly byte[] W1 = H("24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512");
    private static readonly byte[] L  = H("0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9");
    private static readonly byte[] X  = H("8b0f3f383905cf3a3bb955ef8fb62e24849dd349a05ca79aafb18041d30cbdb6");
    private static readonly byte[] BigX = H("04af09987a593d3bac8694b123839422c3cc87e37d6b41c1d630f000dd64980e537ae704bcede04ea3bec9b7475b32fa2ca3b684be14d11645e38ea6609eb39e7e");
    private static readonly byte[] Y  = H("2e0895b0e763d6d5a9564433e64ac3cac74ff897f6c3445247ba1bab40082a91");
    private static readonly byte[] BigY = H("04417592620aebf9fd203616bbb9f121b730c258b286f890c5f19fea833a9c900cbe9057bc549a3e19975be9927f0e7614f08d1f0a108eede5fd7eb5624584a4f4");
    private static readonly byte[] Z  = H("0471a35282d2026f36bf3ceb38fcf87e3112a4452f46e9f7b47fd769cfb570145b62589c76b7aa1eb6080a832e5332c36898426912e29c40ef9e9c742eee82bf30");
    private static readonly byte[] V  = H("046718981bf15bc4db538fc1f1c1d058cb0eececf1dbe1b1ea08a4e25275d382e82b348c8131d8ed669d169c2e03a858db7cf6ca2853a4071251a39fbe8cfc39bc");
    private static readonly byte[] Ka = H("f9cab9adcc0ed8e5a4db11a8505914b2");
    private static readonly byte[] Ke = H("801db297654816eb4f02868129b9dc89");
    private static readonly byte[] KcA = H("0d248d7d19234f1486b2efba5179c52d");
    private static readonly byte[] KcB = H("556291df26d705a2caedd6474dd0079b");

    private readonly Spake2Plus _spake = new();

    [Fact]
    public void ProverShare_X_matches_vector()
    {
        // X = x·P + w0·M
        Assert.Equal(Hex(BigX), Hex(_spake.ComputeX(X, W0)));
    }

    [Fact]
    public void VerifierShare_Y_matches_vector()
    {
        // Y = y·P + w0·N
        Assert.Equal(Hex(BigY), Hex(_spake.ComputeY(Y, W0)));
    }

    [Fact]
    public void Verifier_L_matches_vector()
    {
        // L = w1·P
        Assert.Equal(Hex(L), Hex(_spake.ComputeL(W1)));
    }

    [Fact]
    public void Verifier_Z_and_V_match_vector()
    {
        // Z = y·(X − w0·M), V = y·L
        var (z, v) = _spake.ComputeVerifierZV(Y, BigX, W0, L);
        Assert.Equal(Hex(Z), Hex(z));
        Assert.Equal(Hex(V), Hex(v));
    }

    [Fact]
    public void Transcript_yields_Ka_Ke_KcA_KcB()
    {
        var tt = Spake2Plus.BuildTranscript(
            Context, ProverId, VerifierId,
            _spake.MUncompressed, _spake.NUncompressed,
            BigX, BigY, Z, V, W0);

        var (ka, ke) = Spake2Plus.DeriveKaKe(tt);
        Assert.Equal(Hex(Ka), Hex(ka));
        Assert.Equal(Hex(Ke), Hex(ke));

        var (kcA, kcB) = Spake2Plus.DeriveConfirmationKeys(ka);
        Assert.Equal(Hex(KcA), Hex(kcA));
        Assert.Equal(Hex(KcB), Hex(kcB));
    }

    private static byte[] H(string hex) => Convert.FromHexString(hex);
    private static string Hex(ReadOnlySpan<byte> b) => Convert.ToHexString(b).ToLowerInvariant();
}

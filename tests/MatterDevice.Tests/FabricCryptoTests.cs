using MatterDevice.Core.Crypto;

namespace MatterDevice.Tests;

/// <summary>
/// Pins the Compressed Fabric Identifier derivation to the canonical Matter Core Specification test vector
/// (§4.3.2.2 / Appendix F). Getting this exact is interop-critical — it feeds the operational discovery
/// name and the CASE destination-id/IPK derivations — so it's nailed by a known-answer test.
/// </summary>
public class FabricCryptoTests
{
    [Fact]
    public void Compressed_fabric_id_matches_spec_vector()
    {
        // Matter Core Spec test vector:
        //   Root public key (65B), Fabric ID 0x2906C908D115D362  =>  Compressed Fabric ID 87E1B004E235A130
        var rootPublicKey = Convert.FromHexString(
            "044a9f42b1ca4840d37292bbc7f6a7e11e22200c976fc900dbc98a7a383a641cb8" +
            "254a2e56d4e295a847943b4e3897c4a773e930277b4d9fbede8a052686bfacfa");
        const ulong fabricId = 0x2906C908D115D362;

        var compressed = FabricCrypto.CompressedFabricId(rootPublicKey, fabricId);
        Assert.Equal("87E1B004E235A130", Convert.ToHexString(compressed));
    }

    [Fact]
    public void Operational_ipk_is_16_bytes_and_deterministic()
    {
        var compressed = Convert.FromHexString("87E1B004E235A130");
        var epoch = Convert.FromHexString("0102030405060708090a0b0c0d0e0f10");

        var ipk1 = FabricCrypto.OperationalIpk(epoch, compressed);
        var ipk2 = FabricCrypto.OperationalIpk(epoch, compressed);
        Assert.Equal(16, ipk1.Length);
        Assert.Equal(Convert.ToHexString(ipk1), Convert.ToHexString(ipk2));
        // a different epoch key yields a different IPK
        var other = FabricCrypto.OperationalIpk(Convert.FromHexString("10101010101010101010101010101010"), compressed);
        Assert.NotEqual(Convert.ToHexString(ipk1), Convert.ToHexString(other));
    }
}

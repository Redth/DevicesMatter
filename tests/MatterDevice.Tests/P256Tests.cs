using MatterDevice.Core.Crypto;

namespace MatterDevice.Tests;

/// <summary>
/// Confirms the P-256 primitives CASE relies on: an ephemeral ECDH agreement is symmetric (both parties
/// reach the same raw secret), and the raw 64-byte r‖s signatures round-trip and reject tampering.
/// </summary>
public class P256Tests
{
    [Fact]
    public void Ecdh_agreement_is_symmetric()
    {
        var a = P256KeyPair.Generate();
        var b = P256KeyPair.Generate();

        var ab = a.EcdhSharedSecret(b.PublicKey);
        var ba = b.EcdhSharedSecret(a.PublicKey);

        Assert.Equal(32, ab.Length);
        Assert.Equal(Convert.ToHexString(ab), Convert.ToHexString(ba));
    }

    [Fact]
    public void Signature_round_trips_and_is_64_bytes()
    {
        var key = P256KeyPair.Generate();
        var message = "to-be-signed CASE TBSData"u8.ToArray();

        var sig = key.Sign(message);
        Assert.Equal(64, sig.Length); // raw r‖s, not DER
        Assert.True(P256.Verify(key.PublicKey, message, sig));
    }

    [Fact]
    public void Verify_rejects_tampered_message_and_wrong_key()
    {
        var key = P256KeyPair.Generate();
        var other = P256KeyPair.Generate();
        var message = "hello"u8.ToArray();
        var sig = key.Sign(message);

        Assert.False(P256.Verify(key.PublicKey, "hellp"u8.ToArray(), sig)); // tampered message
        Assert.False(P256.Verify(other.PublicKey, message, sig));            // wrong key
    }

    [Fact]
    public void Key_round_trips_through_private_scalar()
    {
        var key = P256KeyPair.Generate();
        var restored = P256KeyPair.FromPrivateKey(key.PrivateKey);
        Assert.Equal(Convert.ToHexString(key.PublicKey), Convert.ToHexString(restored.PublicKey));

        // a signature from the restored key verifies against the original public key
        var sig = restored.Sign("x"u8.ToArray());
        Assert.True(P256.Verify(key.PublicKey, "x"u8.ToArray(), sig));
    }
}

using MatterDevice.Commissioning.SetupPayload;

namespace MatterDevice.Tests;

/// <summary>
/// Pins the onboarding-payload encoders (QR Base38 + manual pairing code + Verhoeff check digit) to the
/// canonical vectors in connectedhomeip's <c>TestQRCode</c> / <c>TestManualCode</c>. Matching CHIP's
/// output byte-for-byte is what lets a real commissioner consume the codes this device prints.
/// </summary>
public class SetupPayloadTests
{
    [Fact]
    public void QrCode_matches_chip_default_vector()
    {
        // TestHelpers.h GetDefaultPayload(): version 0, VID 12, PID 1, rendezvous=SoftAP,
        // discriminator 128, passcode 2048  =>  kDefaultPayloadQRCode.
        var payload = new MatterSetupPayload
        {
            Version = 0,
            VendorId = 12,
            ProductId = 1,
            Flow = CommissioningFlow.Standard,
            Discovery = DiscoveryCapabilities.SoftAp,
            Discriminator = 128,
            Passcode = 2048,
        };

        Assert.Equal("MT:M5L90MP500K64J00000", payload.ToQrCodeString());
    }

    [Fact]
    public void ManualCode_standard_flow_matches_chip_vector()
    {
        // TestManualCode default payload: passcode 12345679, discriminator 2560 (short 0xA),
        // standard flow  =>  "2412950753" + Verhoeff check digit.
        var payload = new MatterSetupPayload
        {
            Discriminator = 2560,
            Passcode = 12345679,
            Flow = CommissioningFlow.Standard,
        };

        var code = payload.ToManualPairingCode();
        Assert.StartsWith("2412950753", code);
        Assert.Equal(11, code.Length);
        Assert.True(Verhoeff10.Validate(code));
    }

    [Fact]
    public void ManualCode_custom_flow_with_vid_pid_matches_chip_vector()
    {
        // TestManualCode: passcode 12345679, discriminator 2560, custom flow, VID 45367, PID 14526
        //   =>  "64129507534536714526" + Verhoeff check digit (21 digits).
        var payload = new MatterSetupPayload
        {
            Discriminator = 2560,
            Passcode = 12345679,
            Flow = CommissioningFlow.Custom,
            VendorId = 45367,
            ProductId = 14526,
        };

        var code = payload.ToManualPairingCode();
        Assert.StartsWith("64129507534536714526", code);
        Assert.Equal(21, code.Length);
        Assert.True(Verhoeff10.Validate(code));
    }

    [Fact]
    public void Qr_binary_round_trips_through_base38()
    {
        var payload = new MatterSetupPayload
        {
            VendorId = 0xFFF1,
            ProductId = 0x8001,
            Discovery = DiscoveryCapabilities.OnNetwork,
            Discriminator = 3840,
            Passcode = 20202021,
        };

        var qr = payload.ToQrCodeString();
        Assert.StartsWith("MT:", qr);
        var decoded = Base38.Decode(qr[3..]);
        Assert.Equal(payload.ToQrBinary(), decoded);
    }

    [Fact]
    public void Verhoeff_rejects_a_corrupted_code()
    {
        var payload = new MatterSetupPayload { Discriminator = 2560, Passcode = 12345679 };
        var code = payload.ToManualPairingCode().ToCharArray();
        code[0] = code[0] == '9' ? '8' : (char)(code[0] + 1); // flip a digit
        Assert.False(Verhoeff10.Validate(code));
    }
}

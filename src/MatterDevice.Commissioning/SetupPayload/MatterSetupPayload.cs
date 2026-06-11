using System.Text;

namespace MatterDevice.Commissioning.SetupPayload;

/// <summary>Rendezvous / discovery capabilities bitmask (Matter Core Spec §5.1.3.1).</summary>
[Flags]
public enum DiscoveryCapabilities : byte
{
    SoftAp = 1 << 0,
    Ble = 1 << 1,
    OnNetwork = 1 << 2, // IP — the only one this device needs
    WifiPaf = 1 << 3,
}

/// <summary>How the device expects to be commissioned (Matter Core Spec §5.1.3).</summary>
public enum CommissioningFlow : byte
{
    Standard = 0,
    UserIntent = 1,
    Custom = 2,
}

/// <summary>
/// A Matter onboarding payload (Matter Core Spec §5.1) — the vendor/product, discriminator and passcode
/// that produce the device's QR code and manual pairing code. Defaults to on-network (IP) commissioning.
/// </summary>
public sealed class MatterSetupPayload
{
    public byte Version { get; init; }
    public ushort VendorId { get; init; }
    public ushort ProductId { get; init; }
    public CommissioningFlow Flow { get; init; } = CommissioningFlow.Standard;
    public DiscoveryCapabilities Discovery { get; init; } = DiscoveryCapabilities.OnNetwork;

    /// <summary>12-bit discriminator (0–4095).</summary>
    public ushort Discriminator { get; init; }

    /// <summary>27-bit setup passcode (1–99999998, excluding the spec's forbidden values).</summary>
    public uint Passcode { get; init; }

    /// <summary>The 4-bit short discriminator (top 4 bits) used by the manual pairing code.</summary>
    public byte ShortDiscriminator => (byte)((Discriminator >> 8) & 0x0F);

    // ---- QR code ---------------------------------------------------------

    /// <summary>The 11-byte packed QR binary payload (88 bits, little-endian, fields LSB-first).</summary>
    public byte[] ToQrBinary()
    {
        var bits = new BitPacker(11);
        bits.Write(Version, 3);
        bits.Write(VendorId, 16);
        bits.Write(ProductId, 16);
        bits.Write((byte)Flow, 2);
        bits.Write((byte)Discovery, 8);
        bits.Write(Discriminator, 12);
        bits.Write(Passcode, 27);
        bits.Write(0, 4); // padding
        return bits.ToArray();
    }

    /// <summary>The QR code string, e.g. <c>MT:…</c> (prefix + Base38 of the packed payload).</summary>
    public string ToQrCodeString() => "MT:" + Base38.Encode(ToQrBinary());

    // ---- manual pairing code --------------------------------------------

    /// <summary>
    /// The manual pairing code: 11 digits for Standard flow, 21 digits (with VID/PID) otherwise. The
    /// final digit is the Verhoeff check digit.
    /// </summary>
    public string ToManualPairingCode()
    {
        var vidPidPresent = Flow != CommissioningFlow.Standard;

        // chunk1 (1 digit): bits[0..1] = shortDisc[3:2], bit[2] = vid/pid present
        var chunk1 = ((ShortDiscriminator >> 2) & 0x03) | (vidPidPresent ? 0x04 : 0x00);
        // chunk2 (5 digits): bits[0..13] = passcode[13:0], bits[14..15] = shortDisc[1:0]
        var chunk2 = (int)(Passcode & 0x3FFF) | ((ShortDiscriminator & 0x03) << 14);
        // chunk3 (4 digits): bits[0..12] = passcode[26:14]
        var chunk3 = (int)((Passcode >> 14) & 0x1FFF);

        var sb = new StringBuilder();
        sb.Append(chunk1.ToString("D1"));
        sb.Append(chunk2.ToString("D5"));
        sb.Append(chunk3.ToString("D4"));
        if (vidPidPresent)
        {
            sb.Append(VendorId.ToString("D5"));
            sb.Append(ProductId.ToString("D5"));
        }
        sb.Append(Verhoeff10.ComputeCheckChar(sb.ToString()));
        return sb.ToString();
    }

    /// <summary>Writes fixed-width fields LSB-first into a little-endian bit stream.</summary>
    private sealed class BitPacker(int byteLength)
    {
        private readonly byte[] _bytes = new byte[byteLength];
        private int _bitOffset;

        public void Write(uint value, int bitCount)
        {
            for (var i = 0; i < bitCount; i++)
            {
                if ((value & (1u << i)) != 0)
                {
                    var pos = _bitOffset + i;
                    _bytes[pos >> 3] |= (byte)(1 << (pos & 7));
                }
            }
            _bitOffset += bitCount;
        }

        public byte[] ToArray() => _bytes;
    }
}

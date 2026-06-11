using System.Text;

namespace MatterDevice.Commissioning.SetupPayload;

/// <summary>
/// Base38 codec for the Matter QR-code payload (Matter Core Spec §5.1.4.1). Bytes are encoded in chunks
/// of 3 (→5 chars), 2 (→4 chars) or 1 (→2 chars); each chunk is read as a little-endian integer and
/// emitted least-significant character first.
/// </summary>
public static class Base38
{
    private const string Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.";
    private static readonly int[] CharsPerChunk = { 2, 4, 5 }; // index by (bytesInChunk - 1)

    public static string Encode(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder();
        var i = 0;
        while (i < data.Length)
        {
            var chunk = Math.Min(3, data.Length - i);
            uint value = 0;
            for (var k = 0; k < chunk; k++)
                value |= (uint)data[i + k] << (8 * k); // little-endian within chunk

            var outChars = CharsPerChunk[chunk - 1];
            for (var c = 0; c < outChars; c++)
            {
                sb.Append(Alphabet[(int)(value % 38)]);
                value /= 38;
            }
            i += chunk;
        }
        return sb.ToString();
    }

    public static byte[] Decode(string encoded)
    {
        var bytes = new List<byte>();
        var i = 0;
        while (i < encoded.Length)
        {
            var chunkChars = Math.Min(5, encoded.Length - i);
            // map char-count back to byte-count: 2->1, 4->2, 5->3
            var byteCount = chunkChars switch { 2 => 1, 4 => 2, 5 => 3, _ => throw new FormatException("Invalid Base38 chunk length.") };

            uint value = 0;
            for (var c = chunkChars - 1; c >= 0; c--)
            {
                var idx = Alphabet.IndexOf(encoded[i + c]);
                if (idx < 0)
                    throw new FormatException($"Invalid Base38 character '{encoded[i + c]}'.");
                value = value * 38 + (uint)idx;
            }
            for (var k = 0; k < byteCount; k++)
                bytes.Add((byte)(value >> (8 * k)));
            i += chunkChars;
        }
        return bytes.ToArray();
    }
}

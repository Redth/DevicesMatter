namespace MatterDevice.Commissioning.SetupPayload;

/// <summary>
/// Verhoeff (base-10, dihedral group D5) check-digit, as Matter's manual pairing code requires
/// (Matter Core Spec §5.1.5). Ported from <c>connectedhomeip/src/lib/support/verhoeff/Verhoeff10.cpp</c>.
/// Note: Matter uses Verhoeff, <b>not</b> Luhn — a Luhn digit produces codes every commissioner rejects.
/// </summary>
public static class Verhoeff10
{
    private const int Base = 10;

    // D5 multiplication table (row-major 10×10).
    private static readonly byte[,] Mul =
    {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 },
        { 1, 2, 3, 4, 0, 6, 7, 8, 9, 5 },
        { 2, 3, 4, 0, 1, 7, 8, 9, 5, 6 },
        { 3, 4, 0, 1, 2, 8, 9, 5, 6, 7 },
        { 4, 0, 1, 2, 3, 9, 5, 6, 7, 8 },
        { 5, 9, 8, 7, 6, 0, 4, 3, 2, 1 },
        { 6, 5, 9, 8, 7, 1, 0, 4, 3, 2 },
        { 7, 6, 5, 9, 8, 2, 1, 0, 4, 3 },
        { 8, 7, 6, 5, 9, 3, 2, 1, 0, 4 },
        { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 },
    };

    // Permutation base row; Permute applies it `pos` times.
    private static readonly byte[] Perm = { 1, 5, 7, 6, 2, 8, 3, 0, 9, 4 };

    // Multiplicative inverse in D5 (sMultiplyTable inverse / DihedralInvert).
    private static readonly byte[] Inverse = { 0, 4, 3, 2, 1, 5, 6, 7, 8, 9 };

    /// <summary>Computes the check digit (0–9) for a string of decimal digit characters.</summary>
    public static char ComputeCheckChar(ReadOnlySpan<char> digits)
    {
        var c = 0;
        // Iterate right-to-left; position index starts at 1 for the rightmost digit.
        for (var i = 0; i < digits.Length; i++)
        {
            var d = digits[digits.Length - 1 - i] - '0';
            if (d is < 0 or > 9)
                throw new ArgumentException("Non-decimal character in Verhoeff input.", nameof(digits));
            c = Mul[c, Permute(d, i + 1)];
        }
        return (char)('0' + Inverse[c]);
    }

    /// <summary>Validates that the last character of <paramref name="digits"/> is its Verhoeff check digit.</summary>
    public static bool Validate(ReadOnlySpan<char> digits)
    {
        if (digits.Length < 2)
            return false;
        var expected = ComputeCheckChar(digits[..^1]);
        return expected == digits[^1];
    }

    private static int Permute(int value, int iterations)
    {
        var v = value;
        for (var i = 0; i < iterations; i++)
            v = Perm[v];
        return v;
    }
}

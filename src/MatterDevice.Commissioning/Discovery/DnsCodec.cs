using System.Buffers.Binary;
using System.Text;

namespace MatterDevice.Commissioning.Discovery;

/// <summary>Growable big-endian DNS writer. Domain names are written uncompressed.</summary>
public sealed class DnsWriter
{
    private byte[] _b = new byte[256];
    private int _n;

    public void WriteByte(byte v) { Ensure(1); _b[_n++] = v; }
    public void WriteUInt16(ushort v) { Ensure(2); BinaryPrimitives.WriteUInt16BigEndian(_b.AsSpan(_n), v); _n += 2; }
    public void WriteUInt32(uint v) { Ensure(4); BinaryPrimitives.WriteUInt32BigEndian(_b.AsSpan(_n), v); _n += 4; }
    public void WriteRaw(ReadOnlySpan<byte> v) { Ensure(v.Length); v.CopyTo(_b.AsSpan(_n)); _n += v.Length; }

    /// <summary>Writes a domain name as length-prefixed labels terminated by a zero byte.</summary>
    public void WriteName(string name)
    {
        foreach (var label in name.TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var bytes = Encoding.UTF8.GetBytes(label);
            if (bytes.Length > 63)
                throw new ArgumentException($"DNS label too long: {label}");
            WriteByte((byte)bytes.Length);
            WriteRaw(bytes);
        }
        WriteByte(0);
    }

    /// <summary>Writes a record's RDATA prefixed by its 16-bit length.</summary>
    public void WriteLengthPrefixedRData(DnsRecord record)
    {
        var lenPos = _n;
        WriteUInt16(0); // placeholder
        var start = _n;
        record.WriteRData(this);
        var rdlen = (ushort)(_n - start);
        BinaryPrimitives.WriteUInt16BigEndian(_b.AsSpan(lenPos), rdlen);
    }

    public byte[] ToArray() => _b.AsSpan(0, _n).ToArray();

    private void Ensure(int extra)
    {
        if (_n + extra > _b.Length)
            Array.Resize(ref _b, Math.Max(_b.Length * 2, _n + extra));
    }
}

/// <summary>Minimal big-endian DNS reader with name decompression (pointer) support.</summary>
public ref struct DnsReader(ReadOnlySpan<byte> data)
{
    private readonly ReadOnlySpan<byte> _data = data;
    private int _pos = 0;

    public void Skip(int n) => _pos += n;

    public ushort ReadUInt16()
    {
        var v = BinaryPrimitives.ReadUInt16BigEndian(_data.Slice(_pos));
        _pos += 2;
        return v;
    }

    public byte[] ReadBytes(int n)
    {
        var b = _data.Slice(_pos, n).ToArray();
        _pos += n;
        return b;
    }

    public string ReadName()
    {
        var labels = new List<string>();
        var pos = _pos;
        var jumped = false;
        var safety = 0;

        while (true)
        {
            if (safety++ > 128) throw new FormatException("DNS name loop.");
            var len = _data[pos++];
            if (len == 0)
                break;
            if ((len & 0xC0) == 0xC0) // compression pointer
            {
                var ptr = ((len & 0x3F) << 8) | _data[pos++];
                if (!jumped) { _pos = pos; jumped = true; }
                pos = ptr;
                continue;
            }
            labels.Add(Encoding.UTF8.GetString(_data.Slice(pos, len)));
            pos += len;
        }
        if (!jumped) _pos = pos;
        return string.Join('.', labels);
    }
}

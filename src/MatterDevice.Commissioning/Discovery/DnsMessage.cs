using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace MatterDevice.Commissioning.Discovery;

/// <summary>DNS resource-record types used by DNS-SD / mDNS.</summary>
public enum DnsType : ushort
{
    A = 1,
    Ptr = 12,
    Txt = 16,
    Aaaa = 28,
    Srv = 33,
    Any = 255,
}

/// <summary>A single DNS resource record (the subset DNS-SD needs).</summary>
public abstract class DnsRecord(string name, DnsType type, uint ttl)
{
    public string Name { get; } = name;
    public DnsType Type { get; } = type;
    public uint Ttl { get; } = ttl;
    public ushort Class { get; init; } = 0x0001; // IN (cache-flush bit set separately when announcing)

    internal abstract void WriteRData(DnsWriter w);
}

public sealed class PtrRecord(string name, string target, uint ttl = 120) : DnsRecord(name, DnsType.Ptr, ttl)
{
    public string Target { get; } = target;
    internal override void WriteRData(DnsWriter w) => w.WriteName(Target);
}

public sealed class SrvRecord(string name, string target, ushort port, uint ttl = 120) : DnsRecord(name, DnsType.Srv, ttl)
{
    public ushort Priority { get; init; }
    public ushort Weight { get; init; }
    public ushort Port { get; } = port;
    public string Target { get; } = target;

    internal override void WriteRData(DnsWriter w)
    {
        w.WriteUInt16(Priority);
        w.WriteUInt16(Weight);
        w.WriteUInt16(Port);
        w.WriteName(Target);
    }
}

public sealed class TxtRecord(string name, IReadOnlyList<string> entries, uint ttl = 120) : DnsRecord(name, DnsType.Txt, ttl)
{
    public IReadOnlyList<string> Entries { get; } = entries; // each "key=value"
    internal override void WriteRData(DnsWriter w)
    {
        if (Entries.Count == 0)
        {
            w.WriteByte(0); // empty TXT must contain a single zero-length string
            return;
        }
        foreach (var e in Entries)
        {
            var bytes = Encoding.UTF8.GetBytes(e);
            w.WriteByte((byte)bytes.Length);
            w.WriteRaw(bytes);
        }
    }
}

public sealed class AddressRecord : DnsRecord
{
    public IPAddress Address { get; }
    public AddressRecord(string name, IPAddress address, uint ttl = 120)
        : base(name, address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? DnsType.Aaaa : DnsType.A, ttl)
        => Address = address;

    internal override void WriteRData(DnsWriter w) => w.WriteRaw(Address.GetAddressBytes());
}

/// <summary>Builds/parses a DNS message. Names are written uncompressed (valid mDNS; simpler than pointers).</summary>
public static class DnsMessage
{
    public const ushort FlagResponseAuthoritative = 0x8400;

    public static byte[] BuildResponse(IReadOnlyList<DnsRecord> answers, bool cacheFlush = true)
    {
        var w = new DnsWriter();
        w.WriteUInt16(0);                          // transaction id (0 for mDNS)
        w.WriteUInt16(FlagResponseAuthoritative);  // QR=1, AA=1
        w.WriteUInt16(0);                          // questions
        w.WriteUInt16((ushort)answers.Count);      // answer RRs
        w.WriteUInt16(0);                          // authority RRs
        w.WriteUInt16(0);                          // additional RRs

        foreach (var rr in answers)
        {
            w.WriteName(rr.Name);
            w.WriteUInt16((ushort)rr.Type);
            var klass = rr.Class;
            if (cacheFlush && rr.Type != DnsType.Ptr)
                klass |= 0x8000; // cache-flush bit (not on shared PTR records)
            w.WriteUInt16(klass);
            w.WriteUInt32(rr.Ttl);
            w.WriteLengthPrefixedRData(rr);
        }
        return w.ToArray();
    }

    /// <summary>Minimal parser: returns the question names + a flat list of (name,type) answers. For tests/queries.</summary>
    public static DnsParsed Parse(ReadOnlySpan<byte> data)
    {
        var r = new DnsReader(data);
        r.Skip(2); // id
        var flags = r.ReadUInt16();
        var qd = r.ReadUInt16();
        var an = r.ReadUInt16();
        r.Skip(4); // ns + ar counts

        var questions = new List<(string Name, DnsType Type)>();
        for (var i = 0; i < qd; i++)
        {
            var name = r.ReadName();
            var type = (DnsType)r.ReadUInt16();
            r.Skip(2); // qclass
            questions.Add((name, type));
        }
        var answers = new List<(string Name, DnsType Type, byte[] RData)>();
        for (var i = 0; i < an; i++)
        {
            var name = r.ReadName();
            var type = (DnsType)r.ReadUInt16();
            r.Skip(2 + 4); // class + ttl
            var rdlen = r.ReadUInt16();
            answers.Add((name, type, r.ReadBytes(rdlen)));
        }
        return new DnsParsed((flags & 0x8000) != 0, questions, answers);
    }
}

public sealed record DnsParsed(bool IsResponse, List<(string Name, DnsType Type)> Questions, List<(string Name, DnsType Type, byte[] RData)> Answers);

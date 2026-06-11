using System.Net;
using System.Text;
using MatterDevice.Commissioning.Discovery;

namespace MatterDevice.Tests;

/// <summary>
/// Verifies the DNS-SD advertisement encodes to a wire packet that parses back to the expected Matter
/// commissionable records (service PTR, discriminator subtypes, SRV port, and the mandatory TXT keys
/// D / CM / VP). This checks the bytes a commissioner would see, short of a live mDNS resolver.
/// </summary>
public class MdnsTests
{
    [Fact]
    public void Commissionable_announcement_round_trips_with_expected_records()
    {
        var service = new MatterCommissionableService
        {
            Discriminator = 3840,
            VendorId = 0xFFF1,
            ProductId = 0x8001,
            CommissioningMode = 1,
            DeviceName = "Pool Heater",
            Port = 5540,
            Addresses = [IPAddress.Parse("192.168.1.50")],
        };

        var packet = DnsMessage.BuildResponse(service.BuildRecords());
        var parsed = DnsMessage.Parse(packet);

        Assert.True(parsed.IsResponse);

        // service PTR present, pointing at our instance
        var servicePtr = parsed.Answers.Single(a => a.Type == DnsType.Ptr && a.Name == MatterCommissionableService.ServiceType);
        Assert.Equal(DnsType.Ptr, servicePtr.Type);

        // long + short discriminator subtype PTRs present
        Assert.Contains(parsed.Answers, a => a.Name == $"_L3840._sub.{MatterCommissionableService.ServiceType}");
        Assert.Contains(parsed.Answers, a => a.Name == $"_S15._sub.{MatterCommissionableService.ServiceType}"); // 3840>>8 = 15

        // SRV on the instance with port 5540
        var srv = parsed.Answers.Single(a => a.Type == DnsType.Srv);
        var port = (ushort)((srv.RData[4] << 8) | srv.RData[5]); // priority(2)+weight(2)+port(2)
        Assert.Equal(5540, port);

        // TXT carries D / CM / VP
        var txt = parsed.Answers.Single(a => a.Type == DnsType.Txt);
        var txtEntries = DecodeTxt(txt.RData);
        Assert.Contains("D=3840", txtEntries);
        Assert.Contains("CM=1", txtEntries);
        Assert.Contains($"VP={0xFFF1}+{0x8001}", txtEntries);

        // A record for the host
        Assert.Contains(parsed.Answers, a => a.Type == DnsType.A);
    }

    private static List<string> DecodeTxt(byte[] rdata)
    {
        var list = new List<string>();
        var i = 0;
        while (i < rdata.Length)
        {
            var len = rdata[i++];
            if (len == 0) break;
            list.Add(Encoding.UTF8.GetString(rdata, i, len));
            i += len;
        }
        return list;
    }
}

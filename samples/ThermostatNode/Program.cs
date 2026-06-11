using MatterDevice.Commissioning.Discovery;
using MatterDevice.Commissioning.Pase;
using MatterDevice.Commissioning.SetupPayload;
using MatterDevice.Commissioning.Transport;
using MatterDevice.DataModel;
using MatterDevice.DataModel.Clusters;
using Microsoft.Extensions.Logging;

// ── A Matter Thermostat node advertised over IP, ready to be commissioned. ──────────────────────────
//
// This is the spike: it generates an onboarding payload, prints the QR + manual pairing code, advertises
// itself over mDNS as a commissionable node, listens on UDP 5540, and runs the PASE handshake when a
// commissioner connects. PASE is proven (see the test suite); what is NOT yet implemented is the post-
// PASE encrypted session, CASE, and the Interaction Model — so a real controller will commission up to
// "operational" and then the device can't yet serve attribute reads. See docs/00-feasibility.md.

using var loggerFactory = LoggerFactory.Create(b => b.AddSimpleConsole(o => { o.SingleLine = true; o.TimestampFormat = "HH:mm:ss "; }).SetMinimumLevel(LogLevel.Information));
var log = loggerFactory.CreateLogger("ThermostatNode");

// Fixed test commissioning credentials (the well-known CHIP sample passcode/discriminator).
const uint passcode = 20202021;
const ushort discriminator = 3840;
const ushort vendorId = 0xFFF1;   // CSA test vendor
const ushort productId = 0x8001;
var salt = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
const int iterations = 1000;

// ── The device's data model (a single Thermostat endpoint over the pool heater). ────────────────────
var node = new Node();
node.AddEndpoint(0, DeviceType.RootNode);
var thermostat = new ThermostatCluster { LocalTemperatureCentiC = 2880, OccupiedHeatingSetpointCentiC = 2944 }; // 28.8 °C water, 29.44 °C set
node.AddEndpoint(1, DeviceType.Thermostat).AddCluster(thermostat);
log.LogInformation("Data model: endpoint 1 = Thermostat (water {Water:0.0} °C, setpoint {Set:0.0} °C)",
    thermostat.LocalTemperatureCentiC / 100.0, thermostat.OccupiedHeatingSetpointCentiC / 100.0);

// ── Onboarding payload → QR + manual pairing code. ──────────────────────────────────────────────────
var payload = new MatterSetupPayload
{
    VendorId = vendorId,
    ProductId = productId,
    Discovery = DiscoveryCapabilities.OnNetwork,
    Discriminator = discriminator,
    Passcode = passcode,
};
Console.WriteLine();
Console.WriteLine("  ┌────────────────────────────────────────────────────┐");
Console.WriteLine("  │  Commission this device with:                        │");
Console.WriteLine($"  │    QR code:      {payload.ToQrCodeString(),-34} │");
Console.WriteLine($"  │    Manual code:  {payload.ToManualPairingCode(),-34} │");
Console.WriteLine("  └────────────────────────────────────────────────────┘");
Console.WriteLine();

// ── mDNS advertising + UDP transport. ───────────────────────────────────────────────────────────────
var addresses = MdnsResponder.LocalIPv4Addresses();
var service = new MatterCommissionableService
{
    Discriminator = discriminator,
    VendorId = vendorId,
    ProductId = productId,
    CommissioningMode = 1,
    DeviceName = "Pool Heater",
    Addresses = addresses,
};

await using var mdns = new MdnsResponder(service, loggerFactory.CreateLogger<MdnsResponder>());
await using var udp = new MatterUdpServer(
    () => new PaseResponder(passcode, salt, iterations, localSessionId: 0x0001),
    MatterUdpServer.DefaultPort,
    loggerFactory.CreateLogger<MatterUdpServer>());

udp.SessionEstablished += session =>
    log.LogInformation("🎉 PASE complete — session keys established (attestation challenge {Hex}…)",
        Convert.ToHexString(session.AttestationChallenge.AsSpan(0, 4)));

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

log.LogInformation("Advertising on {Count} address(es); listening on UDP {Port}. Ctrl+C to stop.",
    addresses.Count, MatterUdpServer.DefaultPort);

try
{
    await Task.WhenAll(mdns.RunAsync(cts.Token), udp.RunAsync(cts.Token));
}
catch (OperationCanceledException) { /* shutting down */ }

log.LogInformation("Stopped.");

using System.Security.Cryptography;
using MatterDevice.Commissioning;
using MatterDevice.Commissioning.Discovery;
using MatterDevice.Commissioning.OperationalCredentials;
using MatterDevice.Commissioning.SetupPayload;
using MatterDevice.Commissioning.Transport;
using MatterDevice.Core.Crypto;
using MatterDevice.DataModel;
using MatterDevice.DataModel.Clusters;
using Microsoft.Extensions.Logging;

// ── A full Matter Thermostat node: advertise over IP, then commission to operational. ───────────────
//
// Generates an onboarding payload, prints the QR + manual pairing code, advertises itself over mDNS, and
// listens on UDP 5540. A controller can then run the whole flow against it — PASE, attestation/CSR/AddNOC
// over the encrypted session, CASE, and Interaction-Model reads/invokes — all through MatterDeviceNode.
//
// Caveat for live controllers: this build signs operational certificates over the Matter-TLV TBS rather
// than the X.509 DER TBS, and ships placeholder (not CHIP-test) attestation certs, so chip-tool/Apple/HA
// validation of the cert chain is the remaining interop step. See docs/01-milestone1-progress.md.

using var loggerFactory = LoggerFactory.Create(b => b.AddSimpleConsole(o => { o.SingleLine = true; o.TimestampFormat = "HH:mm:ss "; }).SetMinimumLevel(LogLevel.Information));
var log = loggerFactory.CreateLogger("ThermostatNode");

const uint passcode = 20202021;
const ushort discriminator = 3840;
const ushort vendorId = 0xFFF1;
const ushort productId = 0x8001;

// ── Data model: a Thermostat over the pool heater. ──────────────────────────────────────────────────
var node = new Node();
node.AddEndpoint(0, DeviceType.RootNode)
    .AddCluster(new BasicInformationCluster(vendorId, "MatterDevice.NET", productId, "Pool Heater", "MD-0001"))
    .AddCluster(new GeneralCommissioningCluster())
    .AddCluster(new OperationalCredentialsCluster());
var thermostat = new ThermostatCluster { LocalTemperatureCentiC = 2880, OccupiedHeatingSetpointCentiC = 2944 };
node.AddEndpoint(1, DeviceType.Thermostat).AddCluster(thermostat);
node.AddDescriptors(); // Descriptor cluster on every endpoint (commissioner enumerates the node)
log.LogInformation("Thermostat: water {Water:0.0} °C, setpoint {Set:0.0} °C",
    thermostat.LocalTemperatureCentiC / 100.0, thermostat.OccupiedHeatingSetpointCentiC / 100.0);

// ── The device node (placeholder attestation certs — see the caveat above). ─────────────────────────
var dacKey = P256KeyPair.Generate();
var device = new MatterDeviceNode(new MatterDeviceOptions
{
    Passcode = passcode,
    PaseSalt = RandomNumberGenerator.GetBytes(32),
    Attestation = new DeviceAttestationProvider(dacKey,
        RandomNumberGenerator.GetBytes(64), RandomNumberGenerator.GetBytes(64), RandomNumberGenerator.GetBytes(128)),
    DataModel = node,
}, loggerFactory.CreateLogger<MatterDeviceNode>());

// ── Onboarding payload → QR + manual pairing code. ──────────────────────────────────────────────────
var payload = new MatterSetupPayload
{
    VendorId = vendorId, ProductId = productId,
    Discovery = DiscoveryCapabilities.OnNetwork, Discriminator = discriminator, Passcode = passcode,
};
Console.WriteLine();
Console.WriteLine("  ┌────────────────────────────────────────────────────┐");
Console.WriteLine("  │  Commission this device with:                        │");
Console.WriteLine($"  │    QR code:      {payload.ToQrCodeString(),-34} │");
Console.WriteLine($"  │    Manual code:  {payload.ToManualPairingCode(),-34} │");
Console.WriteLine("  └────────────────────────────────────────────────────┘");
Console.WriteLine();

// ── mDNS advertising + UDP host. ────────────────────────────────────────────────────────────────────
var service = new MatterCommissionableService
{
    Discriminator = discriminator, VendorId = vendorId, ProductId = productId,
    CommissioningMode = 1, DeviceName = "Pool Heater", Addresses = MdnsResponder.LocalIPv4Addresses(),
};
await using var mdns = new MdnsResponder(service, loggerFactory.CreateLogger<MdnsResponder>());
await using var host = new MatterUdpHost(device, MatterUdpHost.DefaultPort, loggerFactory.CreateLogger<MatterUdpHost>());

// Once commissioned, advertise the operational service so a controller can reconnect via CASE.
device.FabricCommissioned += fabric =>
{
    var operational = new MatterOperationalService
    {
        CompressedFabricIdHex = Convert.ToHexString(fabric.CompressedFabricId),
        NodeIdHex = fabric.NodeId.ToString("X16"),
        HostName = service.HostName,
        Addresses = service.Addresses,
    };
    log.LogInformation("Commissioned onto fabric {Fabric:X} — advertising operational {Instance}",
        fabric.FabricId, operational.InstanceName);
    _ = mdns.AdvertiseAsync(operational);
};

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
log.LogInformation("Advertising + listening on UDP {Port}. Ctrl+C to stop.", MatterUdpHost.DefaultPort);

try { await Task.WhenAll(mdns.RunAsync(cts.Token), host.RunAsync(cts.Token)); }
catch (OperationCanceledException) { /* shutting down */ }

log.LogInformation("Stopped. {Fabrics} fabric(s), {Sessions} session(s).", device.Fabrics.Count, device.Sessions.Count);

# Building a real Matter device with MatterDevice.NET

This library is now a working Matter **device** stack: a controller (matter.js verified — Apple/Google/HA
in principle, modulo production attestation certs) can **discover, commission, interview, subscribe to,
read, and control** a device you build with it. This guide shows how to build one.

## The shape of a device

```csharp
// 1. Define the data model: endpoints + clusters.
var node = new Node();
node.AddEndpoint(0, DeviceType.RootNode)
    .AddCluster(new BasicInformationCluster(vendorId, "Acme", productId, "Pool Heater", "SN-123"))
    .AddCluster(new GeneralCommissioningCluster())
    .AddCluster(new OperationalCredentialsCluster())
    .AddCluster(new AccessControlCluster());

var thermostat = new ThermostatCluster { LocalTemperatureCentiC = 2880 };
node.AddEndpoint(1, DeviceType.Thermostat).AddCluster(thermostat);
node.AddDescriptors();   // adds the Descriptor cluster to every endpoint (required)

// 2. React to controller writes — your device logic.
thermostat.AttributeChanged += (_, attr) =>
{
    if (attr == ThermostatCluster.OccupiedHeatingSetpointId)
        heater.SetTarget(thermostat.OccupiedHeatingSetpointCentiC / 100.0);
};

// 3. Push live sensor updates — subscribers get them automatically.
sensor.OnReading += celsius => thermostat.SetAttribute(ThermostatCluster.LocalTemperatureId, (short)(celsius * 100));

// 4. Run it: onboarding payload + mDNS + UDP transport.
var device = new MatterDeviceNode(new MatterDeviceOptions
{
    Passcode = 20202021, PaseSalt = RandomNumberGenerator.GetBytes(32),
    Attestation = attestationProvider,   // DAC/PAI/CD (CHIP test certs for dev)
    DataModel = node,
});
await using var mdns = new MdnsResponder(commissionableService);
await using var host = new MatterUdpHost(device);
device.FabricCommissioned += fabric => _ = mdns.AdvertiseAsync(operationalService(fabric));
await Task.WhenAll(mdns.RunAsync(ct), host.RunAsync(ct));
```

The full worked example is [`samples/ThermostatNode`](../samples/ThermostatNode).

## What you get for free

- **Commissioning** — PASE, attestation, CSR, AddNOC, CASE, the commissioning clusters.
- **Interaction Model** — Read (incl. wildcard `*/*/*` with automatic chunking), Write (with validation +
  change events), Invoke (route to a command handler), Subscribe (priming + live + heartbeat reports).
- **Discovery** — commissionable + operational mDNS.

## Writing a custom cluster

Subclass `Cluster`. Seed attributes with `Set`, mark controller-writable ones with `MarkWritable`, push
live changes with `SetAttribute` (bumps the data version + notifies subscribers), and override
`WriteAttribute` to validate. Structured attributes (structs/lists) use `TlvStruct`/`TlvArray`.

```csharp
public sealed class OnOffCluster : Cluster
{
    public const uint ClusterId = 0x0006;
    public const uint OnOffId = 0x0000;
    public OnOffCluster() : base(ClusterId, "On/Off")
    {
        Set(OnOffId, false);
        MarkWritable(OnOffId);
        AcceptedCommands = [0x00, 0x01, 0x02]; // Off, On, Toggle
    }
}
```

To handle a command, pass a `CommandHandler` to `MatterDeviceOptions.ApplicationCommandHandler` and switch
on `cmd.Path.Cluster`/`cmd.Path.Command`.

## Remaining for a shipping product

The protocol is complete and interop-proven; these are the productization gaps:

- **Production attestation certs.** Dev uses CHIP test DAC/PAI/CD (accepted by matter.js/HA). Apple/Google
  require a CSA-issued DAC chaining to a real PAA + a real Vendor ID (CSA membership + certification).
- **Persistence.** The fabric table, ACL, and session/subscription state are in-memory; persist them so a
  device survives a restart without re-commissioning. (`FabricTable`/`SessionManager` are the seams.)
- **MRP robustness.** Retransmission/backoff and dedup are minimal; harden for lossy networks.
- **Multi-fabric & admin.** RemoveFabric, multiple controllers, CASE resumption, fail-safe timer enforcement.
- **More clusters / device types.** Generate the cluster definitions from the CSA XML for breadth.
- **IPv6 / multi-NIC mDNS** hardening and known-answer suppression.
- **Group messaging** (multicast) and **Events** (the IM event path) if your device needs them.

None of these are unknowns — the cryptographic and wire-format risks are retired and validated against a
real controller. They are engineering breadth + the CSA certification process.

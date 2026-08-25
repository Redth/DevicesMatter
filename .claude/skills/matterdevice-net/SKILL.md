---
name: matterdevice-net
description: >-
  Building, hosting, debugging and testing Matter devices and bridges with
  MatterDevice.NET (MatterDevice.Core / .DataModel / .Commissioning / .Testing) —
  a pure-C# Matter device stack with no chip/C++ dependency.
  Covers node/endpoint/cluster modelling, pushing live state so controllers
  actually see it, hosting (UDP, mDNS, fabric persistence, QR/setup payload),
  the subscription and chunked-reporting model, ecosystem quirks (Apple Home /
  HomeKit), runtime diagnostics, and in-process device tests.
  USE FOR: "MatterDevice.NET", "DevicesMatter", "Matter device in C#",
  "Matter bridge .NET", "MatterDeviceNode", "MatterUdpHost", "SetAttribute",
  "AttributeChanged", "commissioning code / QR", "device not updating in Apple
  Home", "HomeKit shows stale value", "session keeps dropping", "ReportData",
  "subscription not reporting", "MatterTestController".
  DO NOT USE FOR: writing a Matter *controller/client* app (this stack is the
  device side), Thread/BLE transport (IP only), Zigbee/Z-Wave, or HomeKit
  Accessory Protocol (HAP) work that isn't Matter.
---

# Building Matter devices with MatterDevice.NET

A pure-C#/.NET Matter **device** stack: PASE + CASE, operational credentials, the Interaction Model, mDNS discovery and setup payloads — no chip stack, no Node, no C++. You model a device, hand it a transport, and real ecosystem controllers commission it.

**Direction matters.** This library implements the *device* (responder) side. It does not drive other people's Matter devices; there's no controller/client app in here. The one exception is `MatterDevice.Testing`, which plays controller purely so you can test your own device in-process.

## The packages

| Package | What's in it |
|---|---|
| `MatterDevice.Core` | TLV, crypto (SPAKE2+, P-256, AEAD), message framing, sessions, fabrics, certificates |
| `MatterDevice.DataModel` | `Node` / `Endpoint` / `Cluster`, the built-in clusters, Interaction Model codecs |
| `MatterDevice.Commissioning` | `MatterDeviceNode` (the orchestrator), PASE/CASE, UDP host, mDNS, setup payload, fabric persistence |
| `MatterDevice.Testing` | `MatterTestController` / `MatterTestDevice` — commission and drive your device in a unit test |

## The rule that matters most: `SetAttribute`, not `Set`

A cluster has two ways to write an attribute, and only one of them tells the controller.

```csharp
// Reports: bumps DataVersion, raises AttributeChanged, node pushes a ReportData.
thermostat.SetAttribute(ThermostatCluster.LocalTemperatureId, (short)2650);
thermostat.LocalTemperatureCentiC = 2650;   // built-in setters report (they call SetAttribute)

// SILENT: stores the value, no event, no report. Constructor seeding ONLY.
Set(SomeAttributeId, value);                // protected — inside your own cluster
```

The silent path is dangerous precisely because it *looks* correct: the value stores, reads back, and answers a `ReadRequest` with the right number. Only a subscribed controller notices, and what it notices is that your device never changed. **If you write a custom cluster, every property that models live device state must use `SetAttribute`.** Use `Set` only in the constructor, to seed initial values before anything is subscribed.

The library's own clusters follow this rule and a test enforces it — see `ClusterReportingTests`. Mirror that test if you add clusters.

## Shape of a device

```csharp
var node = new Node();
node.AddEndpoint(0, DeviceType.RootNode);                       // endpoint 0 is mandatory

var thermostat = new ThermostatCluster();
node.AddEndpoint(1, DeviceType.Thermostat).AddCluster(thermostat);

var device = new MatterDeviceNode(new MatterDeviceOptions
{
    Passcode    = 20202021,
    PaseSalt    = RandomNumberGenerator.GetBytes(16),
    Attestation = attestationProvider,                          // DAC/PAI/CD
    DataModel   = node,
    FabricStore = new FileFabricStore(path),                    // pairings survive restart
    ApplicationCommandHandler = HandleCommand,                  // controller → device commands
});
```

Then push live readings in whenever your backend polls:

```csharp
thermostat.LocalTemperatureCentiC = (short)Math.Round(waterTempC * 100);
thermostat.RunningState = firing ? ThermostatCluster.RunningStateHeatOn : (ushort)0;
```

## Hosting

`MatterUdpHost` owns the socket **and the tick loop** — don't hand-roll either:

```csharp
await using var host = new MatterUdpHost(device, logger: logger);
device.RestoreFabrics();                    // after wiring FabricCommissioned
await host.RunAsync(cancellationToken);     // pumps datagrams + calls TickAsync every second
```

`TickAsync` is what sends heartbeat reports and reaps dead sessions. If you build your own transport instead, you must call it on a timer — a device that never ticks stops reporting and never cleans up sessions.

For pairing, `MatterSetupPayload` produces both codes — `ToQrCodeString()` (the `MT:…` string you render as a QR with any QR library) and `ToManualPairingCode()`. `MdnsResponder` handles commissionable/operational advertising.

## Subscriptions and reporting — the part that bites

A controller subscribes (Apple Home subscribes to the **whole node** — wildcard paths, easily 150+ attributes), then expects:

- a report whenever a subscribed attribute changes, and
- a report at least every so often even when nothing changes.

Two invariants make that actually work on a real network:

1. **Reports must be chunked.** A whole-node snapshot is far bigger than the ~1280-byte UDP MTU. Reports are split into MTU-sized chunks, each released only when the peer acks the previous one. An oversized datagram isn't an error — it's silently dropped, and the device looks fine from its own side while the controller sees nothing.
2. **Heartbeat must outpace the idle reaper.** Sessions with no *inbound* traffic are evicted. Controllers go quiet when state is stable, so the device sends periodic reports whose acks keep the session alive. The heartbeat interval must stay comfortably below the session idle timeout or live controllers get reaped every few minutes.

Symptom of getting either wrong: the controller connects, works briefly, then goes unresponsive and reconnects on a cycle, and values never update.

## Diagnosing a device that "works but doesn't update"

Expose these from a health endpoint — session counts alone won't tell you:

```csharp
device.Sessions        // live secure sessions
device.Fabrics         // commissioned fabrics
device.Subscriptions   // what each controller watches + LastReportUtc  ← the useful one
```

```csharp
device.SessionEstablished += s => ...;
device.SessionEvicted    += (s, reason) => ...;   // Idle | PeerReconnected | CapacityExceeded
device.SubscriptionAdded += s => ...;
device.SubscriptionRemoved += s => ...;
device.ReportSent        += (sub, attributeCount, chunkCount) => ...;
```

Read them like this:

| What you see | What it means |
|---|---|
| Sessions > 0, **`Subscriptions` empty** | Controller connected but isn't watching anything — changes will never be pushed |
| `LastReportUtc` far in the past | Reports aren't going out; check the attribute is being set with `SetAttribute` |
| Repeated `SessionEvicted(Idle)` on a cycle | Controller isn't acking — usually reports aren't reaching it (chunking/MTU) |
| `SessionEvicted(PeerReconnected)` | Normal: a controller re-established CASE |
| Log: `no covering subscription` on attr change | The changed path isn't in any subscription |

## Testing your device

`MatterDevice.Testing` commissions your node in-process over the real wire format and speaks the Interaction Model to it. Use it instead of asserting on internal state — the whole class of bugs above is invisible from inside the device.

```csharp
var device     = MatterTestDevice.Create(node);
var controller = MatterTestController.Commission(device);

controller.Subscribe([new AttributePath(null, null, null)]);   // wildcard, like Apple Home

thermostat.LocalTemperatureCentiC = 2650;                       // device-side change
var reported = await controller.ReceiveReportAsync();           // acks every chunk, reassembles

Assert.Contains(reported, a => Convert.ToInt64(a.Value) == 2650);
controller.AssertAllDatagramsWithinMtu();                       // nothing too big for the wire
```

`ReceiveReportAsync` throws `TimeoutException` when no report arrives — which is exactly the failure a silent setter or a missing subscription produces. Also available: `Read`, `Write`, `Invoke`, `DeviceDatagramSizes`, `HasPendingReport`.

## Ecosystem quirks (learned the hard way)

**Apple Home / HomeKit**

- It subscribes **wildcard** to the entire node, so chunking is mandatory, not an optimisation.
- It omits the Source Node ID from the message header, carrying the node id only in the AEAD nonce. Devices must handle that.
- It goes **completely silent** when state is stable — no polling, no keepalive traffic. Idle-eviction logic that assumes chatty controllers will kill live sessions.
- **Thermostat**: it only shows "Heating" vs "Idle" from `ThermostatRunningState` (0x0029). Without it there's no flame indicator. It also only enables the Off/Heat mode control when `ControlSequenceOfOperation` is present — otherwise the mode toggle is inert while the temperature dial still works.
- **On/Off** can't express speed, percentage, or fault state. A device with a fault or a speed needs a richer cluster (e.g. FanControl) or a second endpoint; there's no vendor error-code vocabulary to lean on.
- A controller waiting to see its own write reflected on a subscription will **revert the control in the UI** if no report comes back — so a write handler that doesn't end in a reported change looks broken to the user.

**General**

- Sensor device types map to whatever cluster you attach — a pressure reading modelled on the wrong cluster surfaces as the wrong unit (e.g. humidity %) in the ecosystem's UI.
- Fabrics persist; sessions don't. After a restart, a controller using a pre-restart session gets a `SessionNotFound` status so it re-establishes via CASE immediately instead of waiting out a retransmit timeout.

## Writing a custom cluster

```csharp
public sealed class MyCluster : Cluster
{
    public const uint ClusterId = 0x1234;
    public const uint ReadingId = 0x0000;

    public MyCluster() : base(ClusterId, "My")
    {
        Set(ReadingId, (short)0);          // seed silently — constructor only
        MarkWritable(ReadingId);           // if controllers may write it
    }

    public short Reading
    {
        get => (short)(Get(ReadingId) ?? (short)0);
        set => SetAttribute(ReadingId, value);   // live state ⇒ must report
    }

    // Optional: validate controller writes.
    public override WriteStatus WriteAttribute(uint attributeId, object? value) =>
        attributeId == ReadingId && Convert.ToInt64(value) is < 0 or > 1000
            ? WriteStatus.ConstraintError
            : base.WriteAttribute(attributeId, value);
}
```

Then cover it with a `MatterTestController` test that subscribes, changes `Reading`, and asserts the report arrives.

## Gotcha checklist

- [ ] Every live-state property uses `SetAttribute`; `Set` appears only in constructors
- [ ] `TickAsync` runs on a timer (free if you use `MatterUdpHost`)
- [ ] `RestoreFabrics()` is called at startup, after wiring `FabricCommissioned`
- [ ] `FabricStore` is configured, or pairings vanish on restart
- [ ] Endpoint 0 with `DeviceType.RootNode` exists
- [ ] Thermostats set `ThermostatRunningState` and `ControlSequenceOfOperation`
- [ ] A test asserts a real report reaches a subscribed controller, not just that a value was stored

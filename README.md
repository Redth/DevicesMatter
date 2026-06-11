# MatterDevice.NET

A pure-C#/.NET implementation of the **device / bridge side** of the
[Matter](https://csa-iot.org/all-solutions/matter/) smart-home protocol — so a .NET process can
*be* a Matter device (or a bridge exposing many devices) that Apple Home, Google Home, Amazon
Alexa, and Home Assistant can commission and control directly over IP, with **no HomeBridge and no
C++/Node sidecar**.

> **Status: research + spike complete — GO.** The hardest piece (PASE/SPAKE2+ commissioning crypto) is
> implemented and **proven byte-exact against the official CHIP test vectors**, and a **full PASE
> handshake completes over real UDP sockets**. See [`docs/00-feasibility.md`](docs/00-feasibility.md)
> for the verdict, the subsystem work-map, and the roadmap; [`BRIEF.md`](BRIEF.md) for the original
> mission.

## What works today

**Spike (commissioning crypto + discovery):**
- **Matter TLV** codec (`MatterDevice.Core/Tlv`)
- **SPAKE2+** over P-256 in the Matter convention — proven against CHIP `SPAKE2P_RFC_test_vectors.h`
- **Message framing** + **PASE** (PBKDFParamRequest…Pake3, StatusReport)
- **Full PASE handshake** end-to-end: device + commissioner derive identical session keys, in-process
  and over **loopback UDP**
- **Onboarding payload** — QR (Base38) + manual pairing code (Verhoeff), pinned to CHIP vectors
- **mDNS** commissionable advertising (`_matterc._udp`, `_L`/`_S` subtypes, SRV/TXT) — announces live
- **`ThermostatNode` sample** — advertises over IP, prints the QR + manual code, runs PASE on UDP 5540

**Milestone 1 progress (toward "commissions to operational"):**
- **AES-CCM secure messaging** — proven with the real PASE-derived session keys (portable: BCL on
  Linux/Windows, BouncyCastle on macOS)
- **Interaction Model** — Read (ReadRequest↔ReportData, incl. wildcards) and Invoke
  (InvokeRequest↔InvokeResponse) over the data model
- **Commissioning clusters** — Basic Information + General Commissioning, driven through the IM

Not yet: CASE, device attestation + Matter cert format, the rest of the cluster library, persistence,
and the live chip-tool/HA validation — see [`docs/01-milestone1-progress.md`](docs/01-milestone1-progress.md).

## Build / test / run

```bash
dotnet test                                   # 27 tests: SPAKE2+ KAT, PASE, AES-CCM, IM, clusters, setup payload, mDNS
dotnet run --project samples/ThermostatNode   # advertise + accept commissioning (Ctrl+C to stop)
```

## Why this exists

The two existing .NET Matter libraries — [`dotnet-matter`](https://github.com/tomasmcguinness/dotnet-matter)
and [`MatterDotNet`](https://github.com/SmartHomeOS/MatterDotNet) — are both **controllers** (they
commission and drive *other* Matter devices). There is no mature .NET stack for the **device side**
(being the thing that gets controlled). This project aims to fill that gap, IP/network-only
(no Thread, no BLE).

The immediate motivating consumer is a separate monorepo,
`~/code/PoolEquipmentIntegrations`, which has working C# clients for Raypak heaters and Pentair
pumps and wants to surface them to Matter as a bridge.

# MatterDevice.NET

A pure-C#/.NET implementation of the **device / bridge side** of the
[Matter](https://csa-iot.org/all-solutions/matter/) smart-home protocol — so a .NET process can
*be* a Matter device (or a bridge exposing many devices) that Apple Home, Google Home, Amazon
Alexa, and Home Assistant can commission and control directly over IP, with **no HomeBridge and no
C++/Node sidecar**.

> **Status: ✅ matter.js — an independent Matter controller — fully commissions the device.** The whole
> journey runs against a real third-party controller over UDP: mDNS discovery → PASE/SPAKE2+ → encrypted
> Interaction-Model reads → ArmFailSafe → device attestation → CSR → AddNOC (X.509-DER cert chain
> validated) → CASE → CommissioningComplete → `🎉 COMMISSIONED`. See
> [`tools/interop-controller`](tools/interop-controller) to reproduce it. The full stack is also proven
> in-process with 47 tests, crypto pinned to CHIP/spec/matter.js known-answer vectors.
> [`docs/01-milestone1-progress.md`](docs/01-milestone1-progress.md) tracks what's next (operational
> subscriptions, CHIP production attestation certs); [`docs/00-feasibility.md`](docs/00-feasibility.md)
> has the verdict; [`BRIEF.md`](BRIEF.md) the mission.

## What works today (all proven end-to-end)

- **TLV / framing / MRP**, **AES-CCM** secure messaging, **P-256** ECDH/ECDSA
- **PASE / SPAKE2+** — proven against CHIP `SPAKE2P_RFC_test_vectors.h`; full handshake in-proc + UDP
- **CASE** — Sigma1/2/3 operational session; both sides derive identical keys
- **Fabric crypto** — compressed-fabric-id (KAT vs the spec vector) + operational IPK
- **Matter certificates** — TLV codec (tags verified vs `CHIPCert.h`), RCAC/NOC generation + chain validation
- **Attestation + Operational Credentials** — AttestationRequest / CSRRequest / AddTrustedRoot / AddNOC → installs a fabric
- **Interaction Model** — Read + Invoke (with command response data) over the data model
- **Clusters** — Basic Information, General Commissioning, Thermostat
- **Orchestrator + transport** — `MatterDeviceNode` sequences the whole flow; `MatterUdpHost` over UDP 5540
- **Onboarding payload** (QR + manual code, CHIP-pinned) + **mDNS** commissionable advertising
- **`ThermostatNode` sample** — a runnable device: advertise → commission → operational

The capstone test commissions the device through one `ProcessDatagram` entry point as real framed/encrypted
messages, then reads the thermostat over the operational CASE session.

## Build / test / run

```bash
dotnet test                                   # 44 tests across every layer (SPAKE2+/CASE/AES-CCM KATs, full commissioning)
dotnet run --project samples/ThermostatNode   # a full commissionable device (Ctrl+C to stop)
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

# MatterDevice.NET

A pure-C#/.NET implementation of the **device / bridge side** of the
[Matter](https://csa-iot.org/all-solutions/matter/) smart-home protocol — so a .NET process can
*be* a Matter device (or a bridge exposing many devices) that Apple Home, Google Home, Amazon
Alexa, and Home Assistant can commission and control directly over IP, with **no HomeBridge and no
C++/Node sidecar**.

> **Status: research + spike.** This repo starts as a feasibility investigation and a minimal
> proof-of-concept. See [`BRIEF.md`](BRIEF.md) for the full mission, what's already known, and the
> scope of the first pass.

## Why this exists

The two existing .NET Matter libraries — [`dotnet-matter`](https://github.com/tomasmcguinness/dotnet-matter)
and [`MatterDotNet`](https://github.com/SmartHomeOS/MatterDotNet) — are both **controllers** (they
commission and drive *other* Matter devices). There is no mature .NET stack for the **device side**
(being the thing that gets controlled). This project aims to fill that gap, IP/network-only
(no Thread, no BLE).

The immediate motivating consumer is a separate monorepo,
`~/code/PoolEquipmentIntegrations`, which has working C# clients for Raypak heaters and Pentair
pumps and wants to surface them to Matter as a bridge.

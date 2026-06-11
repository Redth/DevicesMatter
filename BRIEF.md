# Kickoff brief — bring the Matter **device side** to C#/.NET

You are starting a fresh project in its own repo (`~/code/MatterDevice.NET`). This brief is
self-contained: it carries all the context from the conversation that spawned you. Read it fully
before doing anything.

## The mission

Implement the **device / bridge side** of the Matter protocol in **pure C#/.NET 10**, so a .NET
process can present itself as one or more Matter devices that commodity Matter controllers
(Apple Home, Google Home, Alexa, Home Assistant) can **commission and control over the LAN**.

Hard constraints / preferences from the user:

- **IP / network only.** No Thread, no BLE. The target device is a software process already on the
  Wi-Fi/Ethernet LAN, so it can be commissioned **on-network** (mDNS / DNS-SD), which sidesteps the
  BLE commissioning transport entirely.
- **No HomeBridge, no Node.js sidecar, no C++ P/Invoke.** The whole point is a native .NET stack.
  (Those alternatives were explicitly considered and rejected in favor of this — don't quietly fall
  back to them.)
- Reusable as a general protocol library, not pool-specific.

## This first pass: **research + spike** (do NOT try to ship a full stack)

The user chose "research + spike" for this session. Deliver, in order:

1. **A feasibility + work-map document** (write it to `docs/00-feasibility.md`). Break the device
   side into its real subsystems and assess each for effort/risk:
   - **Commissioning / onboarding** — on-network (IP) commissioning flow: PASE (Passcode-Authenticated
     Session Establishment, SPAKE2+), the setup passcode / discriminator, QR + manual pairing code
     generation, commissionable-node mDNS advertising (`_matterc._udp`), then operational `_matter._tcp`.
   - **Secure transport / session layer** — Matter message framing, MRP (Message Reliability
     Protocol) over UDP, CASE (Certificate-Authenticated Session Establishment) for operational
     sessions, session keys.
   - **Crypto** — SPAKE2+, certificate handling (Matter uses a DER/Matter-TLV cert format), the
     Distinguished Access Control, AES-CCM, HKDF, the **Device Attestation Certificate (DAC)** chain.
     Note what .NET BCL gives you (`System.Security.Cryptography`, `System.Formats.Cbor`, `System.Formats.Asn1`)
     vs. what needs a third-party lib or hand-rolling (SPAKE2+ and the secp256r1 ops are the likely gaps).
   - **Data model** — the Interaction Model: Nodes → Endpoints → Clusters → Attributes/Commands/Events.
     Matter **TLV** encoding (its own tag-length-value format, *not* CBOR — be careful here).
   - **Clusters needed for the spike** — Descriptor, Basic Information, General Commissioning,
     Network Commissioning, Operational Credentials, plus **Thermostat** (the demo device type) and the
     **Bridged Device Basic Information / Aggregator** pattern for the eventual bridge.
   - **Device attestation** — for *real* controllers (esp. Apple) the DAC must chain to a CSA-approved
     PAA. Document the test-cert path: the CHIP **test PAA/PAI/DAC** set works with HA and Google in
     dev; Apple is stricter. Be explicit that production attestation needs CSA certification and a real
     vendor ID — out of scope, but the spike should use the well-known test vendor/cert material.
2. **A minimal proof-of-concept skeleton** (a buildable .NET solution) that proves the *riskiest*
   piece end-to-end. Recommended target for the spike: get a controller to **discover and begin
   commissioning** a .NET node — i.e. advertise a commissionable node over mDNS and complete (or get
   as far as possible through) the PASE/SPAKE2+ handshake. Even a partial handshake that a real
   commissioner accepts is a hugely de-risking result. If full PASE is too big for one pass, get mDNS
   advertising + the Matter UDP message framing + first handshake message exchanging, and document
   exactly where it stops.
3. **A clear go/no-go writeup** at the end: what's proven, what the remaining big rocks are, and a
   recommended roadmap + estimate for a full device-side build. **Report back before committing to the
   full build** — the user wants to decide after seeing the spike.

### Explicitly out of scope for this pass
- A complete, conformant cluster library.
- CSA certification / production attestation.
- The actual Raypak/Pentair bridge wiring (that comes later, in the consumer repo).
- Thread, BLE, Wi-Fi commissioning of *headless* devices.

## What's already known / decided (don't re-derive)

- **Device side vs controller side** are different stacks. The existing .NET libs are controllers and
  do **not** help directly, but **read their source** — `MatterDotNet`
  (https://github.com/SmartHomeOS/MatterDotNet) and `dotnet-matter`
  (https://github.com/tomasmcguinness/dotnet-matter) already implement Matter **TLV, message framing,
  MRP, SPAKE2+, CASE, and the crypto** from the controller perspective. Huge amounts of that
  (TLV codec, crypto primitives, transport) are **role-agnostic and reusable** — mine them. This is
  your single biggest accelerator; start there.
- **matter.js** (https://github.com/matter-js/matter.js) is the most mature non-C++ **device-side**
  reference — read its `@matter/protocol` and `BridgedDevicesNode` examples to see how the device role
  is structured (it's TypeScript, but the architecture maps cleanly).
- **connectedhomeip** (https://github.com/project-chip/connectedhomeip) is the canonical spec
  implementation. Its `examples/bridge-app` and `docs/` are the reference for the bridge device type
  and the commissioning flow. The **Matter Core Specification** (CSA, public PDF) is the source of
  truth for TLV, the IM, and cluster definitions.
- **On-network commissioning is the easy transport** and is well-trodden by software bridges — confirm
  the mDNS service types and TXT keys (`D`, `CM`, `VP`, etc.) from the spec.
- The **Bridge** device-type pattern (one node, an Aggregator endpoint, N Bridged Node endpoints) is
  the right model for surfacing many proprietary devices — but for the spike, a **single Thermostat
  node** is enough.

## Conventions to match (from the sibling monorepo)
- **.NET 10** (`global.json` pins `10.0.100`, `rollForward: latestMinor`). Nullable + ImplicitUsings on.
- `TreatWarningsAsErrors` true. `Microsoft.Extensions.Logging` for logging, `Microsoft.Extensions.Options`
  for options objects. Central Package Management (`Directory.Packages.props`) is the monorepo style —
  adopt it here too.
- `System.Formats.Cbor` and `System.Formats.Asn1` are in-box and useful for cert/attestation work
  (CBOR is **not** Matter TLV, but shows up around attestation/CD).
- Keep it minimal and idiomatic; favor the BCL before pulling third-party crypto. SPAKE2+ over
  secp256r1 is the one piece likely to need `BouncyCastle` or a careful hand-roll on top of
  `System.Security.Cryptography` EC primitives — evaluate both.

## Suggested repo layout (propose your own if better)
```
src/
  MatterDevice.Core        # TLV codec, message framing, MRP, sessions, crypto
  MatterDevice.Commissioning  # PASE/SPAKE2+, mDNS advertising, pairing-code/QR
  MatterDevice.DataModel   # Node/Endpoint/Cluster model + the handful of spike clusters
samples/
  ThermostatNode           # the spike: a single Matter Thermostat over IP
docs/
  00-feasibility.md
tests/
  MatterDevice.Tests       # TLV + crypto vectors (use spec/CHIP test vectors)
```

## Definition of done for this session
- `docs/00-feasibility.md` written, with the subsystem work-map + effort/risk + recommended roadmap.
- A buildable skeleton solution committed (`dotnet build` clean).
- The riskiest-slice spike attempted and its result documented (how far commissioning got, with a
  real controller if reachable, else against the spec/CHIP test vectors).
- A short go/no-go summary at the top of the feasibility doc.
- Don't expand scope past the spike without checking back.

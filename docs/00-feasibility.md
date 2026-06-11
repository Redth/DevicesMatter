# Matter device-side in pure C#/.NET — feasibility + work-map

> Research-and-spike pass. Goal: decide whether a **pure-C#/.NET implementation of the Matter device /
> bridge side** (IP-only, no HomeBridge/Node/C++) is viable, and map the work. See [`../BRIEF.md`](../BRIEF.md)
> for the mission.

## Go / no-go

**GO.** Nothing in the device-side stack requires leaving managed .NET, and the single highest-risk
piece — the **PASE/SPAKE2+ commissioning crypto** — is now **implemented and proven byte-exact against
the official CHIP test vectors**, with a **full PASE handshake completing over real UDP sockets** in
this spike. The remaining work is large but it is *breadth, not unknowns*: the hard cryptographic and
wire-format risks are retired; what's left (CASE, the Interaction Model, the cluster library, message
encryption, attestation) is well-specified plumbing that the same approach extends to.

The one genuine external dependency is **device attestation** for production: Apple/Google require a
Device Attestation Certificate chaining to a CSA-approved PAA, which needs CSA membership + a real
Vendor ID. That gates *shipping a certified product*, not *building/using the stack* — the CHIP **test**
PAA/PAI/DAC and test vendor ID work with Home Assistant and (in dev) Google for bring-up.

## What this spike proves (all green, 17 tests)

| Capability | Evidence | Status |
|---|---|---|
| **Matter TLV** encode/decode (ints, bools, strings, byte strings, containers, nested) | `TlvWriter`/`TlvReader` + round-trip tests | ✅ working |
| **SPAKE2+** over P-256 in the Matter (draft-bar-01) convention | **Known-answer test vs CHIP `SPAKE2P_RFC_test_vectors.h`**: X, Y, L, Z, V, Ka, Ke, KcA, KcB reproduce byte-for-byte | ✅ **proven** |
| **Message framing** (message header + protocol header, unsecured session) | `MatterMessage` + round-trip tests | ✅ working |
| **PASE** PBKDFParamRequest/Response, Pake1/2/3, StatusReport | TLV codecs + `PaseResponder` state machine | ✅ working |
| **Full PASE handshake** (device + commissioner derive identical session keys) | in-process test + **loopback-UDP test** (5 messages as real datagrams) | ✅ **proven end-to-end** |
| **Onboarding payload** (QR Base38 + manual pairing code + Verhoeff) | pinned to CHIP `TestQRCode`/`TestManualCode`; sample emits the canonical `34970112332` | ✅ **proven** |
| **mDNS commissionable advertising** (`_matterc._udp`, `_L`/`_S` subtypes, SRV/TXT) | DNS-SD codec + announce/respond; record-set round-trip test; **announces live on the LAN** | 🟡 built, not yet verified against a live commissioner |
| **Runnable device** (`ThermostatNode` sample) | advertises, prints QR/manual, listens on UDP 5540, completes PASE | ✅ runs |

What is **not** done (by design for a spike): the **post-PASE encrypted session** (AES-CCM), **CASE**
(operational session), the **Interaction Model** (Read/Subscribe/Invoke), the **cluster library**, and
**attestation**. A real controller will discover the node, run PASE, and then expect to continue into
attestation + CASE + IM, which the device cannot yet answer. The spike deliberately stops at "PASE
completes."

## How the BCL/ecosystem covers the crypto

| Primitive | Source | Notes |
|---|---|---|
| SHA-256, HMAC-SHA256, HKDF, PBKDF2 | **.NET BCL** (`System.Security.Cryptography`) | all in-box, no dependency |
| AES-CCM (message/session encryption) | **.NET BCL** `AesCcm` on Linux/Windows; **BouncyCastle** CCM on macOS | ✅ done. ⚠️ the BCL's `AesCcm` throws `PlatformNotSupportedException` on **macOS** — `MatterAead` falls back to BouncyCastle there automatically, so dev-on-Mac works and prod-on-Linux uses the BCL |
| EC point add / scalar-mult arbitrary points / decompression (SPAKE2+) | **BouncyCastle** | the BCL's EC types don't expose raw point math; this is the one third-party dep, isolated in `Spake2Plus` |
| X.509 / DER / Matter-TLV certs (attestation, NOC) | **.NET BCL** (`System.Formats.Asn1`, `X509Certificate2`) + a Matter-cert ↔ X.509 converter to write | in-box building blocks |
| Ed25519/ECDSA P-256 signatures (attestation, CASE) | **.NET BCL** (`ECDsa`) | in-box |

Conclusion: **only SPAKE2+ needs BouncyCastle**; everything else is BCL. A later option is to hand-roll
the handful of P-256 point operations on `System.Security.Cryptography` primitives to drop BouncyCastle,
but it isn't worth it now — BouncyCastle is well-tested and the SPAKE2+ surface is tiny.

## Subsystem work-map (effort / risk)

Effort is rough dev-time for a single experienced engineer; risk is *interop/unknowns* risk.

| Subsystem | Effort | Risk | Notes |
|---|---|---|---|
| TLV codec | ✅ done | — | extend with float/profile tags as IM needs them |
| Message framing (unsecured) | ✅ done | — | |
| **Message encryption** (AES-CCM, 13-byte nonce, AAD = header, privacy) | S (2–4 d) | Low | BCL `AesCcm`; nonce/AAD documented; needed before CASE/IM |
| **MRP** (retransmit, dedup window, standalone-ack timing) | M (3–5 d) | Low–Med | spike has piggyback acks only; full reliability/dedup is mechanical |
| SPAKE2+ / PASE | ✅ done | — | proven |
| **mDNS** hardening (multi-NIC, IPv6, name compression, known-answer suppression, conflict) | M (4–6 d) | Med | spike advertises; interop polish is the work. **First external validation step.** |
| **CASE** (Sigma1/2/3, operational session from NOC) | L (1–2 wk) | Med | same crypto family as PASE (SPAKE→ECDH+sign); needs certs + the IM to be useful |
| **Operational credentials** (CSR, install NOC/Root, fabric table) | M–L (1–2 wk) | Med | Operational Credentials cluster + persistent fabric store |
| **Device attestation** (DAC chain, attestation challenge response, CD) | M (1 wk) | **Med–High** (process, not code) | code is straightforward; **getting a trusted DAC for production needs CSA + a Vendor ID**. Test certs for dev. |
| **Interaction Model** (Read / Subscribe / Invoke / Report, status codes, paths) | XL (3–4 wk) | Med | the largest single chunk; the protocol that makes the device *do* anything post-commissioning |
| **Cluster library** (Descriptor, Basic Info, General/Network Commissioning, Operational Credentials, Access Control, + device-type clusters e.g. Thermostat) | L–XL (ongoing) | Low–Med | mechanical but voluminous; generate from the CSA cluster XML |
| **Bridge** (Aggregator + Bridged Node endpoints, dynamic add/remove) | M (1 wk) | Low | once the IM + Descriptor cluster exist, the bridge pattern is a thin layer; `DataModel` already sketches it |
| Persistence (fabrics, ACL, counters, CASE resumption) | M (3–5 d) | Low | a small KV store |

**Critical path to a controller-usable device:** message encryption → MRP → attestation (test certs) →
operational credentials → CASE → Interaction Model + the commissioning clusters. That is the sequence a
commissioner walks after PASE; until the whole chain exists, commissioning won't *finish*.

## Recommended roadmap

1. **Milestone 1 — "commissions to operational" (the next real goal).** Message encryption (AES-CCM) →
   MRP hardening → mDNS interop validation against **chip-tool** and **Home Assistant** → attestation
   with CHIP **test** certs → Operational Credentials + CASE → the minimum commissioning clusters
   (General Commissioning, Network Commissioning, Operational Credentials, Basic Information, Descriptor).
   Exit test: `chip-tool pairing code …` (or HA) fully commissions the node onto a fabric. *~5–7 weeks.*
2. **Milestone 2 — "serves its state."** Interaction Model (Read/Subscribe/Invoke) + the Thermostat
   cluster, so a commissioned controller can read temperature/setpoint and change mode/setpoint. Exit
   test: Apple Home / HA shows and controls the thermostat. *~3–4 weeks.*
3. **Milestone 3 — "bridge."** Aggregator + Bridged Node endpoints; wire the pool-equipment integrations
   (Raypak/Pentair) in as bridged Thermostat/derived endpoints. *~1–2 weeks.*
4. **Milestone 4 — productionization.** CASE resumption, persistence, multi-fabric, robustness, and —
   if shipping — CSA certification + a real DAC.

Rough total to a genuinely useful pool-equipment Matter bridge (test-cert attestation, not CSA-certified):
**~10–14 weeks** of focused work. The spike retired the scariest ~1–2 weeks of that (the SPAKE2+/PASE
crypto) and proved the architecture.

## On commissioning transport & attestation (the two things people get wrong)

- **IP-only commissioning is fine.** The node advertises `_matterc._udp` over mDNS; a commissioner
  already on the LAN discovers it and runs PASE over UDP/5540 — no BLE, no Thread. The spike does exactly
  this. (`_matter._tcp` is the operational service name and is a spec quirk — operational traffic is
  still UDP.)
- **Attestation is the real gate, and it's organizational not technical.** The DAC must chain to a
  CSA-approved PAA. For development, the CHIP **test** PAA/PAI/DAC + test Vendor ID (0xFFF1–0xFFF4) are
  accepted by Home Assistant and Google's dev path; **Apple is strict and effectively needs production
  certs**. Shipping a certified product needs CSA membership and a Vendor ID. None of this blocks the
  build or in-house use — it blocks the "certified" label.

## Reusing the existing .NET Matter libraries

`MatterDotNet` and `dotnet-matter` are **controllers**, but their **TLV, crypto, and transport code is
role-agnostic**. This spike wrote its own (small, proven) TLV + SPAKE2+ to keep the device side clean and
fully understood, but for Milestones 1–2 it is worth **lifting their CASE, certificate/Matter-TLV, and
AES-CCM code** rather than reimplementing — that could shave a couple of weeks. Recommended: vendor in
their cert + CASE modules behind our own interfaces.

## Bottom line

A pure-.NET Matter **device/bridge** is viable and the hardest crypto is done and proven. Recommend
proceeding to **Milestone 1** (commission-to-operational against chip-tool/HA), with the explicit
checkpoint that **mDNS interop against a live commissioner** is the first thing to validate, since it's
the one built-but-unproven piece in this spike.

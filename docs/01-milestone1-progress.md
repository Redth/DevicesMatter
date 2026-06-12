# Milestone 1 progress — "commissions to operational"

The path from the spike (PASE proven) to a node a real controller can fully commission. See
[`00-feasibility.md`](00-feasibility.md) for the overall plan.

## Done — the full commissioning stack is built and proven (44 tests green)

Every layer is implemented in pure C#/.NET and proven end-to-end **in-process and over loopback UDP**,
with crypto primitives pinned to CHIP/spec known-answer vectors.

| Layer | What | Proof |
|---|---|---|
| **TLV / framing / MRP** | codec, message + protocol headers, dedup window | round-trip + dedup tests |
| **PASE / SPAKE2+** | full PBKDFParamRequest…Pake3 + StatusReport | KAT vs CHIP `SPAKE2P_RFC_test_vectors.h`; full handshake (in-proc + UDP) |
| **AES-CCM secure messaging** | encrypt/decrypt, nonce/AAD per spec; portable (BCL + BouncyCastle) | round-trip with real PASE keys; tamper/wrong-key rejected |
| **P-256 ECDH/ECDSA** | ephemeral ECDH, raw r‖s signatures, CSR create/parse | symmetry + sign/verify tests |
| **Fabric crypto** | compressed-fabric-id, operational IPK | **KAT vs the Matter spec compressed-fabric-id vector** |
| **Matter certificates** | TLV cert codec (tags verified vs `CHIPCert.h` + OID generator), RCAC/NOC generation + chain validation | round-trip + chain + tamper tests |
| **CASE** | Sigma1/2/3, destination-id fabric selection, S2K/S3K/SEK schedule | **full handshake: both sides derive identical operational keys** |
| **Attestation + Operational Credentials** | AttestationRequest, CSRRequest, AddTrustedRoot, AddNOC → installs a fabric | full flow test, DAC-signed |
| **Interaction Model** | Read (ReadRequest↔ReportData) + Invoke (InvokeRequest↔InvokeResponse, with command response data) | round-trip + dispatch tests |
| **Clusters** | Basic Information, General Commissioning, Thermostat | read identity / arm-failsafe / read temperature over IM |
| **Orchestrator + transport** | `MatterDeviceNode` sequences PASE → encrypted IM commissioning → CASE → encrypted IM; `MatterUdpHost` over UDP 5540 | **capstone test: a commissioner drives the whole flow as real framed/encrypted messages and reads the thermostat over the operational session** |

The `ThermostatNode` sample is a runnable device: it advertises over mDNS, prints the QR + manual code,
and accepts the complete commissioning flow through one `ProcessDatagram` entry point.

## ✅ matter.js fully commissions the device — 2026-06

**Milestone 1 is achieved.** The real [matter.js](https://github.com/project-chip/matter.js) controller
(no shared code) commissions the `ThermostatNode` sample end to end and prints
`🎉 COMMISSIONED — nodeId …`: mDNS discovery → PASE → `GetInitialData` reads → ArmFailSafe → device
attestation → CSRRequest → AddTrustedRoot + **AddNOC (statusCode 0)** → **CASE** operational reconnect →
**CommissioningComplete (errorCode 0)**. See [`../tools/interop-controller`](../tools/interop-controller).

Real bugs found and fixed by diffing against matter.js along the way: the CASE **S2K salt** includes
`SHA256(Sigma1)` (research had said it didn't); **InvokeResponseIB** tags were swapped (`command[0]`,
`status[1]`); the **NOC `extKeyUsage`** was dropped on re-encode; the **DN OID arcs** (icac `.1.3`, rcac
`.1.4`). The DER conversion is pinned by KATs against matter.js's actual root + NOC certs.

**Update — fully operational.** Writes, subscriptions, report chunking, and the Access Control cluster are
now done, and matter.js drives the device end to end: it **interviews** (reads the whole data model via a
chunked `*/*/*`), **subscribes** (live attribute reports), and **reads + writes** attributes (control
applied). See [`02-building-devices.md`](02-building-devices.md). Remaining items are productization
(CHIP **production** attestation certs for Apple/Google, persistence across restarts, MRP hardening,
multi-fabric, more clusters) — engineering breadth + CSA certification, not protocol unknowns.

## Earlier interop checkpoint (superseded by the above)

Tested with the real [matter.js](https://github.com/project-chip/matter.js) controller (no shared code);
see [`../tools/interop-controller`](../tools/interop-controller). Confirmed working over real UDP:

- ✅ **mDNS discovery** — matter.js finds the device and parses every TXT/subtype record correctly.
- ✅ **PASE / SPAKE2+** — full handshake completes with MRP acks: *"Paired successfully."*
- ✅ **Encrypted session + IM transport** — our device decrypts matter.js's read requests and returns
  encrypted ReportData.
- ⛔ Stops at **`GetInitialData`**: matter.js reads `GeneralCommissioning.BasicCommissioningInfo`,
  `OperationalCredentials.commissionedFabrics`, `NetworkCommissioning`, … and our device returns *empty*
  reports for attributes it doesn't expose yet.

So the entire transport/crypto stack (discovery, PASE, MRP, AES-CCM, encrypted IM) is **interop-proven
against a third party** — a much stronger result than our own loopback harness. The remaining work below
is now concretely ordered by what matter.js asks for next.

## Remaining for byte-level interop with a real controller (chip-tool / Apple / HA)

The protocol logic is complete and internally consistent. What stands between this and a controller
actually commissioning the device on the LAN:

1. **X.509 DER certificate signature domain.** Operational certs are currently signed over the Matter-TLV
   TBS; chip-tool verifies the chain by converting TLV→X.509 DER and checking the signature over the DER
   TBSCertificate. Implement the deterministic Matter-TLV ↔ X.509 DER conversion (BCL `System.Formats.Asn1`)
   so the cert chain validates on a real controller. *Mechanical, but exacting.* The CASE/attestation
   handshake signatures (TBSData/attestationElements) are already over the correct domains.
2. **CHIP test attestation certs.** Ship the real CHIP `credentials/test` DAC/PAI/PAA + Certification
   Declaration (test Vendor ID 0xFFF1) instead of placeholders, so the controller's attestation verifier
   accepts the device (HA accepts the test chain; Apple/Google need production certs).
3. **Descriptor + Network Commissioning clusters.** Descriptor needs array-of-struct attribute encoding
   (DeviceTypeList/ServerList/PartsList); Network Commissioning is needed for the on-network path's
   commissioning-complete checks.
4. **mDNS interop hardening.** Multi-NIC/IPv6, name compression, known-answer suppression — and the first
   real test against a live commissioner (the advertiser is built but unverified against one).
5. **General Commissioning command semantics.** ArmFailSafe timer + CommissioningComplete gating (currently
   accepted as no-ops); operational discovery (`_matter._tcp`) advertisement after commissioning.
6. **Persistence + multi-fabric.** Persist the fabric table / sessions; support >1 fabric and CASE resumption.

Estimate to a controller-validated commission: **~2–4 weeks**, dominated by item 1 (DER conversion) and
item 4 (live mDNS interop). The cryptographically hard parts — SPAKE2+, CASE, the key schedules,
attestation signing — are done and KAT/handshake-proven.

## Notes for whoever continues
- The cert signature domain is isolated in `OperationalCredentials.Sign`/`VerifySignature`; swapping it to
  DER-TBS is the one change that flips cert-chain interop on.
- `InteractionDispatcher.WriteValue`/`ReadValue` is where array/struct attribute support (Descriptor) goes.
- Lifting CHIP's test credential byte arrays from `credentials/examples/DeviceAttestationCredsExample.cpp`
  is the fast path for item 2.
- `MatterDeviceNode.ProcessDatagram` is the single integration point; a real run is just the UDP host
  pumping packets (already wired in `MatterUdpHost`).

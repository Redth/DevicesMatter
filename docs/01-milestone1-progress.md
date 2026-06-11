# Milestone 1 progress — "commissions to operational"

Tracking the path from the spike (PASE proven) to a node a real controller can fully commission.
See [`00-feasibility.md`](00-feasibility.md) for the overall plan.

## Done (all test-proven — 27 tests green)

| Layer | What | Where |
|---|---|---|
| **AES-CCM secure messaging** | message encryption/decryption, 13-byte nonce, AAD = header; portable (BCL `AesCcm` on Linux/Windows, BouncyCastle on macOS) | `Core/Crypto/MatterAead`, `Core/Messaging/MatterMessage.EncodeSecure/DecodeSecure` |
| **Interaction Model (Read)** | ReadRequest ↔ ReportData; path resolution incl. wildcards; type-aware value codec | `DataModel/InteractionModel/ReadInteraction`, `InteractionDispatcher` |
| **Interaction Model (Invoke)** | InvokeRequest ↔ InvokeResponse (CommandStatusIB); command routing to a handler | `DataModel/InteractionModel/InvokeInteraction` |
| **Commissioning clusters (partial)** | Basic Information (identity), General Commissioning (breadcrumb/regulatory + command IDs), wired through the IM | `DataModel/Clusters/BasicInformationCluster`, `GeneralCommissioningCluster` |

Proven interactions: a commissioner reads vendor/product identity, reads thermostat temperature/setpoint,
arms the fail-safe + completes, and invokes a setpoint-change command — all over the real IM codecs.

## Remaining for Milestone 1 (the big rock — task 7)

In dependency order:

1. **Matter certificate format** — the Matter-TLV operational certificate encoding and a ↔ X.509
   converter (BCL `System.Formats.Asn1` + `X509Certificate2`). Needed by both attestation and CASE.
2. **Device attestation** — `AttestationRequest`/`CertificateChainRequest`/`CSRRequest` on the
   **Operational Credentials cluster** (0x003E), signing with the **DAC** (use CHIP **test** DAC/PAI/PAA +
   test Vendor ID for bring-up). The attestation challenge comes from the PASE session keys (already
   derived). Certification Declaration is a fixed CMS blob (CHIP test CD for dev).
3. **Operational credentials install** — `CSRRequest` → `AddTrustedRootCertificate` → `AddNOC`; build a
   **fabric table** keyed by the installed NOC/root; persist it.
4. **CASE** (Sigma1/2/3, Secure Channel opcodes 0x30–0x32) — operational session from the NOC. Same
   crypto family as PASE (ECDH on P-256 + signatures with the NOC key + the existing HKDF/AES-CCM); the
   `Spake2Plus`/`MatterAead`/HKDF pieces are reusable. CASE uses a **non-empty** HKDF salt (unlike PASE).
5. **Network Commissioning + Descriptor clusters** — Descriptor needs **array-of-struct attribute
   encoding** (DeviceTypeList/ServerList/PartsList), a small extension to the value codec.
6. **Secure-session plumbing in `MatterUdpServer`** — after PASE/CASE, route encrypted IM messages
   (`DecodeSecure`/`EncodeSecure` are ready), maintain per-session counters + MRP dedup, and dispatch to
   the `InteractionDispatcher`.
7. **Live validation** — commission with **chip-tool** (`pairing code …`) and **Home Assistant**; this is
   also where the built-but-unverified **mDNS** advertiser gets its first real-commissioner test.

Estimate for the remainder: **~4–6 weeks**. The reusable crypto (SPAKE2+/ECDH/HKDF/AES-CCM) and the IM
are done, so CASE and attestation are mostly cert plumbing + wiring rather than new cryptographic risk.

## Notes for whoever picks this up
- The **attestation challenge** and **session keys** already fall out of `PaseSession` — CASE will add a
  second session type but reuses `MatterAead` and the HKDF helpers in `Spake2Plus`.
- Lifting CASE + Matter-cert code from **MatterDotNet** (controller, but role-agnostic crypto/cert) is
  recommended over reimplementing — see the feasibility doc.
- The `InteractionDispatcher.WriteValue`/`ReadValue` pair is the place to add array/struct support for
  Descriptor and for command response-data.

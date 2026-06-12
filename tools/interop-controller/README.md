# Interop controller (matter.js)

A real, independent Matter controller — [matter.js](https://github.com/project-chip/matter.js) — used to
interop-test the `MatterDevice.NET` device. Because it shares no code with our implementation, anything it
can do with our device validates our wire format against a third party.

## Run

```bash
# 1. start the device (separate terminal, from the repo root)
dotnet run --project samples/ThermostatNode

# 2. install + run the controller
cd tools/interop-controller
npm install
node controller.mjs discover     # mDNS discovery only
node controller.mjs              # discover + commission (prints "🎉 COMMISSIONED — nodeId …")
```

## Result: matter.js fully commissions the device ✅ (2026-06)

Against the `ThermostatNode` sample, **matter.js 0.15.6 commissions the device end to end** and reports
`🎉 COMMISSIONED — nodeId …`. The complete flow, all interop-verified over real UDP:

- ✅ **mDNS discovery** — finds the device, parses every TXT/subtype record.
- ✅ **PASE / SPAKE2+** — full handshake with MRP acks: *"Paired successfully."*
- ✅ **Encrypted Interaction Model** — `GetInitialData` reads (BasicCommissioningInfo, Descriptor,
  OperationalCredentials, BasicInformation, …) answered from the data model.
- ✅ **ArmFailSafe / SetRegulatoryConfig** — command responses with `errorCode`.
- ✅ **Device attestation** — CertificateChainRequest + AttestationRequest (DAC-signed).
- ✅ **CSRRequest** — matter.js parses our CSR and builds a NOC.
- ✅ **AddTrustedRootCertificate + AddNOC** — `statusCode 0` (our **X.509-DER cert chain validation**
  accepts matter.js's NOC).
- ✅ **CASE** (operational reconnect) — Sigma1/2/3 complete; *"Successfully reconnected with device."*
- ✅ **CommissioningComplete** — `errorCode 0` over the operational CASE session.

A third-party controller commissioning a pure-.NET Matter device with no shared code — the strongest
possible validation. Several real bugs were found and fixed by diffing against matter.js: the CASE S2K
salt's Sigma1 hash, the swapped `InvokeResponseIB` tags, the NOC `extKeyUsage` round-trip, and the DN OID
arcs. The known-answer tests in `MatterDevice.Tests/CertificateDerTests` pin our DER conversion to
matter.js's actual root + NOC certs.

> `controller.mjs` passes `connectNodeAfterCommissioning: false`, so it resolves when commissioning
> completes. matter.js's *post*-commission persistent subscription (the operational "interview") needs
> SubscribeRequest support on the device — the next operational-usability item. Commissioning itself is
> complete.

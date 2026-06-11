# Interop controller (matter.js)

A real, independent Matter controller — [matter.js](https://github.com/project-chip/matter.js) — used to
interop-test the `MatterDevice.NET` device. Because it shares no code with our implementation, anything it
can do with our device (discover, pair, talk encrypted IM) validates our wire format against a third party.

## Run

```bash
# 1. start the device (separate terminal, from the repo root)
dotnet run --project samples/ThermostatNode

# 2. install + run the controller
cd tools/interop-controller
npm install
node controller.mjs discover     # mDNS discovery only
node controller.mjs              # discover + attempt full commissioning (verbose)
```

## Validated results (2026-06)

Against the `ThermostatNode` sample, matter.js 0.15.6:

- ✅ **mDNS discovery** — finds the device and parses every TXT/subtype record correctly
  (`D=3840, CM=1, VP=65521+32769, DN="Pool Heater"`, `_L3840` subtype, short discriminator 15, address+port).
- ✅ **PASE / SPAKE2+** — completes the full handshake over UDP with MRP acks
  (`PbkdfParamRequest→Response`, `Pake1→Pake2`, `Pake3→StatusReport(success)`):
  *"Pase client: Paired successfully."*
- ✅ **Encrypted secure session + Interaction Model transport** — opens a secure session and our device
  decrypts its read requests and returns encrypted `ReportData`.
- ⛔ **Stops at `GetInitialData`** — matter.js reads `GeneralCommissioning.BasicCommissioningInfo`
  (`failSafeExpiryLengthSeconds`), `OperationalCredentials.commissionedFabrics`, `NetworkCommissioning`,
  etc. Our device returns *empty* reports for attributes it doesn't yet expose, so the controller can't
  proceed. **Next step: expose the commissioning-cluster attributes a controller reads** (Basic­Commissioning­Info,
  Descriptor, OperationalCredentials/NetworkCommissioning attributes), then attestation with CHIP test
  certs, then the X.509-DER cert signature domain for AddNOC. See `docs/01-milestone1-progress.md`.

So every transport/crypto layer (discovery, PASE, MRP, AES-CCM, encrypted IM) is interop-proven against a
real controller; what remains is data-model breadth + the cert/attestation interop items.

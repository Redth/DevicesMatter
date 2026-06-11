// Interop test: drive the MatterDevice.NET device with the matter.js controller (independent impl).
// 1) discover our device over mDNS, 2) attempt to commission it, logging exactly where it gets to.
//
// Usage:  node controller.mjs              (discover + commission)
//         node controller.mjs discover     (discovery only)

import { Environment, Logger, LogLevel, LogFormat } from "@matter/main";
import { CommissioningController } from "@project-chip/matter.js";

const DISCRIMINATOR = 3840;
const PASSCODE = 20202021;
const mode = process.argv[2] ?? "commission";

Logger.level = LogLevel.DEBUG;
Logger.format = LogFormat.ANSI;

const environment = Environment.default;

const controller = new CommissioningController({
    environment: { environment, id: "interop-controller" },
    autoConnect: false,
    adminFabricLabel: "interop",
});

await controller.start();
console.log("\n=== matter.js controller started ===\n");

// ---- discovery ----
console.log(`Discovering commissionable devices with long discriminator ${DISCRIMINATOR} ...`);
const found = await controller.discoverCommissionableDevices(
    { longDiscriminator: DISCRIMINATOR },
    { onIpNetwork: true },
    device => console.log("  discovered:", JSON.stringify(device)),
    15,
);
console.log(`\nDiscovery finished: ${found.length} device(s) found.`);
if (found.length === 0) {
    console.log("✗ Our device was not discovered over mDNS. (Is ThermostatNode running on this host?)");
    await controller.close();
    process.exit(found.length === 0 && mode === "discover" ? 1 : 1);
}
console.log("✓ mDNS discovery interop OK — matter.js can see our device.\n");

if (mode === "discover") {
    await controller.close();
    process.exit(0);
}

// ---- commissioning ----
console.log("Attempting to commission (PASE → attestation → CSR → AddNOC → CASE) ...\n");
try {
    const nodeId = await controller.commissionNode({
        discovery: {
            identifierData: { longDiscriminator: DISCRIMINATOR },
            discoveryCapabilities: { onIpNetwork: true },
        },
        passcode: PASSCODE,
    });
    console.log(`\n🎉 COMMISSIONED — nodeId ${nodeId}`);
} catch (err) {
    console.log(`\n✗ Commissioning stopped: ${err?.message ?? err}`);
    console.log("  (Expected to break at the first not-yet-interop-complete step; the log above shows where.)");
} finally {
    await controller.close();
}
process.exit(0);

// Single-process restart-survival test: commission the device, read it, then (while this script waits)
// the device process is killed and restarted; we then re-read over a fresh CASE session. If the post-restart
// read succeeds, the device persisted its fabric and a paired controller reconnects WITHOUT re-pairing.

import { Environment, Logger, LogLevel } from "@matter/main";
import { CommissioningController } from "@project-chip/matter.js";
import { ThermostatCluster } from "@matter/main/clusters";
import { EndpointNumber } from "@matter/main/types";

Logger.level = LogLevel.ERROR; // keep our own prints clean
const DISCRIMINATOR = 3840, PASSCODE = 20202021;

const controller = new CommissioningController({
    environment: { environment: Environment.default, id: "restart-test" },
    autoConnect: false,
    adminFabricLabel: "restart-test",
});
await controller.start();

const read = async node => {
    const t = node.getClusterClientForDevice(EndpointNumber(1), ThermostatCluster.with("Heating"));
    return (await t.getLocalTemperatureAttribute()) / 100;
};

const nodeId = await controller.commissionNode({
    discovery: { identifierData: { longDiscriminator: DISCRIMINATOR }, discoveryCapabilities: { onIpNetwork: true } },
    passcode: PASSCODE,
});
console.log(`COMMISSIONED ${nodeId}`);
const node = await controller.getNode(nodeId);
console.log(`PRE-RESTART localTemperature = ${await read(node)} °C`);

console.log("=== RESTART_DEVICE_NOW ===");        // the shell watches for this, kills + restarts the device
await new Promise(r => setTimeout(r, 28000));      // window for the restart

console.log("reconnecting over a fresh CASE session …");
try {
    await node.connect?.();                         // re-establish if matter.js dropped the session
    const t = await read(node);
    console.log(`POST-RESTART localTemperature = ${t} °C`);
    console.log("PERSISTENCE_VERIFIED");
} catch (e) {
    console.log(`RECONNECT_FAILED: ${e?.message ?? e}`);
} finally {
    await controller.close();
}
process.exit(0);

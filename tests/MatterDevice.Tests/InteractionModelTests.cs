using MatterDevice.Core.Tlv;
using MatterDevice.DataModel;
using MatterDevice.DataModel.Clusters;
using MatterDevice.DataModel.InteractionModel;

namespace MatterDevice.Tests;

/// <summary>
/// Exercises the Interaction Model skeleton end to end against a Thermostat data model: a controller's
/// ReadRequest resolves to the live attribute value in a ReportData, and an InvokeRequest routes to a
/// command handler that mutates the model. These are the two interactions a commissioned controller uses
/// to read and control the device.
/// </summary>
public class InteractionModelTests
{
    private static Node BuildThermostatNode(out ThermostatCluster thermostat)
    {
        var node = new Node();
        node.AddEndpoint(0, DeviceType.RootNode);
        thermostat = new ThermostatCluster
        {
            LocalTemperatureCentiC = 2880,        // 28.80 °C
            OccupiedHeatingSetpointCentiC = 2944, // 29.44 °C
            SystemMode = ThermostatSystemMode.Heat,
        };
        node.AddEndpoint(1, DeviceType.Thermostat).AddCluster(thermostat);
        return node;
    }

    [Fact]
    public void Read_resolves_thermostat_local_temperature()
    {
        var node = BuildThermostatNode(out _);
        var dispatcher = new InteractionDispatcher(node);

        // Controller asks for endpoint 1 / Thermostat / LocalTemperature.
        var request = ReadInteraction.EncodeRequest(
        [
            new AttributePath(1, ThermostatCluster.ClusterId, ThermostatCluster.LocalTemperatureId),
        ]);

        var paths = ReadInteraction.DecodeRequest(request);
        var reports = dispatcher.Read(paths);
        var wire = ReadInteraction.EncodeReport(reports);

        // Decode the ReportData and pull the value back out.
        var value = ExtractFirstReportedInt(wire);
        Assert.Equal(2880, value);
    }

    [Fact]
    public void Read_wildcard_attribute_returns_all_cluster_attributes()
    {
        var node = BuildThermostatNode(out _);
        var dispatcher = new InteractionDispatcher(node);

        // endpoint 1 / Thermostat / (all attributes)
        var paths = ReadInteraction.DecodeRequest(
            ReadInteraction.EncodeRequest([new AttributePath(1, ThermostatCluster.ClusterId, null)]));
        var reports = dispatcher.Read(paths);

        // Thermostat seeds 3 attributes (local temp, heating setpoint, system mode).
        Assert.Equal(3, reports.Count);
        Assert.All(reports, r => Assert.Equal(ThermostatCluster.ClusterId, r.Path.Cluster));
    }

    [Fact]
    public void Invoke_routes_to_handler_and_mutates_model()
    {
        var node = BuildThermostatNode(out var thermostat);
        var dispatcher = new InteractionDispatcher(node);

        // A "set heating setpoint to 30.00 °C" command (command id 0x05 chosen arbitrarily for the skeleton).
        const uint setpointCommandId = 0x05;
        var request = InvokeInteraction.EncodeRequest(
        [
            new InvokedCommand(new CommandPath(1, ThermostatCluster.ClusterId, setpointCommandId), FieldsTlv: null),
        ]);

        var commands = InvokeInteraction.DecodeRequest(request);
        var results = dispatcher.Invoke(commands, (endpoint, cluster, cmd) =>
        {
            if (cluster is ThermostatCluster t && cmd.Path.Command == setpointCommandId)
            {
                t.OccupiedHeatingSetpointCentiC = 3000;
                return ImStatus.Success;
            }
            return ImStatus.UnsupportedCommand;
        });

        Assert.Single(results);
        Assert.Equal(ImStatus.Success, results[0].Status);
        Assert.Equal(3000, thermostat.OccupiedHeatingSetpointCentiC);

        // The response encodes and the status survives a round-trip.
        var responseWire = InvokeInteraction.EncodeResponse(results);
        Assert.NotEmpty(responseWire);
    }

    [Fact]
    public void Invoke_unknown_cluster_yields_status_error()
    {
        var node = BuildThermostatNode(out _);
        var dispatcher = new InteractionDispatcher(node);

        var commands = InvokeInteraction.DecodeRequest(
            InvokeInteraction.EncodeRequest([new InvokedCommand(new CommandPath(1, 0xDEAD, 0x00), null)]));
        var results = dispatcher.Invoke(commands, (_, _, _) => ImStatus.Success);

        Assert.Equal(ImStatus.UnsupportedCluster, results[0].Status);
    }

    /// <summary>Walks a ReportData TLV to the first AttributeDataIB's data element and returns it as an int.</summary>
    private static long ExtractFirstReportedInt(byte[] reportData)
    {
        long? found = null;
        var r = new TlvReader(reportData);
        r.Read(); // top struct
        r.EnterContainer((ref TlvReader f) =>
        {
            if (f.TagNumber != 1 || !f.IsContainer) return; // AttributeReports array
            f.EnterContainer((ref TlvReader reportIb) =>
            {
                reportIb.EnterContainer((ref TlvReader dataIb) =>
                {
                    if (dataIb.TagNumber == 1) // AttributeDataIB
                    {
                        dataIb.EnterContainer((ref TlvReader field) =>
                        {
                            if (field.TagNumber == 2) // Data
                                found = field.GetInt();
                        });
                    }
                });
            });
        });
        Assert.True(found.HasValue, "No data element found in ReportData.");
        return found!.Value;
    }
}

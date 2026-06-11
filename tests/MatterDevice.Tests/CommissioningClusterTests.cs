using MatterDevice.DataModel;
using MatterDevice.DataModel.Clusters;
using MatterDevice.DataModel.InteractionModel;

namespace MatterDevice.Tests;

/// <summary>
/// Exercises the root-endpoint commissioning clusters (Basic Information, General Commissioning) through
/// the Interaction Model the way a commissioner does early in the flow: reading vendor/product identity,
/// then arming the fail-safe and completing commissioning. Proves the cluster surface + IM dispatch line
/// up — a concrete step of "commissions to operational."
/// </summary>
public class CommissioningClusterTests
{
    private static Node BuildRootNode()
    {
        var node = new Node();
        var root = node.AddEndpoint(0, DeviceType.RootNode);
        root.AddCluster(new BasicInformationCluster(0xFFF1, "Test Vendor", 0x8001, "Pool Heater", "MD-0001"));
        root.AddCluster(new GeneralCommissioningCluster());
        return node;
    }

    [Fact]
    public void Commissioner_reads_basic_information_identity()
    {
        var node = BuildRootNode();
        var dispatcher = new InteractionDispatcher(node);

        var request = ReadInteraction.EncodeRequest(
        [
            new AttributePath(0, BasicInformationCluster.ClusterId, BasicInformationCluster.VendorNameId),
            new AttributePath(0, BasicInformationCluster.ClusterId, BasicInformationCluster.ProductNameId),
            new AttributePath(0, BasicInformationCluster.ClusterId, BasicInformationCluster.VendorIdId),
        ]);

        var reports = dispatcher.Read(ReadInteraction.DecodeRequest(request));
        var decoded = ReadInteraction.DecodeReport(ReadInteraction.EncodeReport(reports));

        Assert.Equal("Test Vendor", Value(decoded, BasicInformationCluster.VendorNameId));
        Assert.Equal("Pool Heater", Value(decoded, BasicInformationCluster.ProductNameId));
        Assert.Equal(0xFFF1UL, Value(decoded, BasicInformationCluster.VendorIdId));
    }

    [Fact]
    public void Commissioner_arms_failsafe_then_completes()
    {
        var node = BuildRootNode();
        var dispatcher = new InteractionDispatcher(node);
        var generalCommissioning = (GeneralCommissioningCluster)node.Endpoints[0].Clusters
            .First(c => c.Id == GeneralCommissioningCluster.ClusterId);

        var armed = false;
        var completed = false;

        CommandHandler handler = (endpoint, cluster, cmd) =>
        {
            if (cluster is not GeneralCommissioningCluster gc) return ImStatus.UnsupportedCluster;
            switch (cmd.Path.Command)
            {
                case GeneralCommissioningCluster.ArmFailSafeId:
                    armed = true;
                    gc.Breadcrumb = 1;
                    return ImStatus.Success;
                case GeneralCommissioningCluster.CommissioningCompleteId:
                    completed = true;
                    return ImStatus.Success;
                default:
                    return ImStatus.UnsupportedCommand;
            }
        };

        // ArmFailSafe
        var armResults = dispatcher.Invoke(
            InvokeInteraction.DecodeRequest(InvokeInteraction.EncodeRequest(
                [new InvokedCommand(new CommandPath(0, GeneralCommissioningCluster.ClusterId, GeneralCommissioningCluster.ArmFailSafeId), null)])),
            handler);
        Assert.Equal(ImStatus.Success, armResults[0].Status);
        Assert.True(armed);
        Assert.Equal(1UL, generalCommissioning.Breadcrumb);

        // CommissioningComplete
        var completeResults = dispatcher.Invoke(
            InvokeInteraction.DecodeRequest(InvokeInteraction.EncodeRequest(
                [new InvokedCommand(new CommandPath(0, GeneralCommissioningCluster.ClusterId, GeneralCommissioningCluster.CommissioningCompleteId), null)])),
            handler);
        Assert.Equal(ImStatus.Success, completeResults[0].Status);
        Assert.True(completed);
    }

    private static object? Value(IReadOnlyList<ReadInteraction.ReportedAttribute> reports, uint attributeId) =>
        reports.First(r => r.Path.Attribute == attributeId).Value;
}

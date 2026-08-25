using MatterDevice.Commissioning;
using MatterDevice.Core.Session;
using MatterDevice.DataModel;
using MatterDevice.DataModel.Clusters;
using MatterDevice.DataModel.InteractionModel;
using MatterDevice.Testing;

namespace MatterDevice.Tests;

/// <summary>
/// Covers the diagnostics surface a host uses to answer "is this device actually talking to its
/// controllers?" — the subscription snapshot and the session/subscription lifecycle events. Session counts
/// alone can't answer it: a controller can hold a healthy-looking session while receiving nothing.
/// </summary>
public class DiagnosticsTests
{
    private static Node BuildNode(out ThermostatCluster thermostat)
    {
        var node = new Node();
        node.AddEndpoint(0, DeviceType.RootNode);
        thermostat = new ThermostatCluster();
        node.AddEndpoint(1, DeviceType.Thermostat).AddCluster(thermostat);
        return node;
    }

    [Fact]
    public async Task Subscription_lifecycle_is_observable()
    {
        var node = BuildNode(out var thermostat);
        var device = MatterTestDevice.Create(node);

        var established = new List<SecureSession>();
        var added = new List<SubscriptionInfo>();
        var reports = new List<(SubscriptionInfo Sub, int Attributes, int Chunks)>();
        device.SessionEstablished += s => established.Add(s);
        device.SubscriptionAdded += s => added.Add(s);
        device.ReportSent += (sub, attributes, chunks) => reports.Add((sub, attributes, chunks));

        var controller = MatterTestController.Commission(device);
        Assert.Single(established);                                   // CASE completed
        Assert.Empty(device.Subscriptions);                           // ...but nothing is watching yet

        controller.Subscribe([new AttributePath(1, ThermostatCluster.ClusterId, null)], maxIntervalCeiling: 120);

        var subscription = Assert.Single(added);
        Assert.Equal(120, subscription.MaxIntervalSeconds);
        Assert.Equal(controller.ControllerNodeId, subscription.PeerNodeId);

        var snapshot = Assert.Single(device.Subscriptions);
        Assert.Equal(subscription.Id, snapshot.Id);
        Assert.Equal(Assert.Single(established).LocalSessionId, snapshot.SessionId);

        // A device-side change reports, and the report is visible to the host with its size.
        var before = snapshot.LastReportUtc;
        thermostat.LocalTemperatureCentiC = 2650;
        await controller.ReceiveReportAsync();

        var sent = Assert.Single(reports);
        Assert.True(sent.Attributes > 0);
        Assert.True(sent.Chunks >= 1);
        Assert.True(device.Subscriptions[0].LastReportUtc >= before, "LastReportUtc should advance after a report");
    }

    [Fact]
    public void Reconnecting_controller_evicts_its_previous_session_with_a_reason()
    {
        // The question that matters when a controller goes flaky is *why* its session went away. A
        // reconnect replacing the old session is healthy; repeated Idle evictions are not.
        var node = BuildNode(out _);
        var device = MatterTestDevice.Create(node);

        var evictions = new List<(SecureSession Session, SessionEvictionReason Reason)>();
        var removedSubscriptions = new List<SubscriptionInfo>();
        device.SessionEvicted += (session, reason) => evictions.Add((session, reason));
        device.SubscriptionRemoved += s => removedSubscriptions.Add(s);

        var first = MatterTestController.Commission(device);
        first.Subscribe([new AttributePath(null, null, null)]);
        Assert.Single(device.Subscriptions);

        // The same controller node re-commissions — its earlier session is replaced, not stacked.
        MatterTestController.Commission(device);

        Assert.Contains(evictions, e => e.Reason == SessionEvictionReason.PeerReconnected);
        Assert.Single(removedSubscriptions);          // the dead session's subscription was dropped
        Assert.Empty(device.Subscriptions);
    }

    [Fact]
    public async Task A_silent_attribute_write_produces_no_report()
    {
        // The inverse of the reporting guarantee, stated as a test so the failure mode is documented: the
        // protected Cluster.Set does not notify, which is why cluster property setters must not use it.
        var node = BuildNode(out var thermostat);
        var device = MatterTestDevice.Create(node);
        var controller = MatterTestController.Commission(device);
        controller.Subscribe([new AttributePath(null, null, null)]);

        // ControlSequenceOfOperation is seeded in the constructor via Set and never mutated afterwards, so
        // nothing should be pushed while the model sits still.
        await Assert.ThrowsAsync<TimeoutException>(
            () => controller.ReceiveReportAsync(TimeSpan.FromMilliseconds(150)));

        // A real update, through the property, does report.
        thermostat.LocalTemperatureCentiC = 2100;
        var reported = await controller.ReceiveReportAsync();
        Assert.Contains(reported, a => Convert.ToInt64(a.Value) == 2100);
    }
}

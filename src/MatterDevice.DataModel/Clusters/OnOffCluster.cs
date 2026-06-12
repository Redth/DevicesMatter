namespace MatterDevice.DataModel.Clusters;

/// <summary>
/// The On/Off cluster (id 0x0006) — the canonical on/off control (Matter Application Cluster Spec §1.5).
/// A controller reads/writes <see cref="OnOffId"/> and invokes Off(0)/On(1)/Toggle(2); wire those to your
/// device via the command handler and by reacting to <see cref="Cluster.AttributeChanged"/>.
/// </summary>
public sealed class OnOffCluster : Cluster
{
    public const uint ClusterId = 0x0006;
    public const uint OnOffId = 0x0000;

    public const uint OffCommandId = 0x00;
    public const uint OnCommandId = 0x01;
    public const uint ToggleCommandId = 0x02;

    public OnOffCluster() : base(ClusterId, "On/Off")
    {
        Set(OnOffId, false);
        MarkWritable(OnOffId);
        AcceptedCommands = [OffCommandId, OnCommandId, ToggleCommandId];
    }

    public bool On
    {
        get => (bool)(Get(OnOffId) ?? false);
        set => SetAttribute(OnOffId, value);
    }
}

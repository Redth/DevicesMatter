using MatterDevice.Core.Tlv;

namespace MatterDevice.DataModel.InteractionModel;

/// <summary>
/// An attribute path (AttributePathIB, Matter Core Spec §10.6.3) — endpoint / cluster / attribute, with
/// optional fields elided. Encoded as a TLV <b>List</b> with context tags.
/// </summary>
public readonly record struct AttributePath(ushort? Endpoint, uint? Cluster, uint? Attribute)
{
    // AttributePathIB context tags.
    private const int TagEndpoint = 2;
    private const int TagCluster = 3;
    private const int TagAttribute = 4;

    public void Write(TlvWriter w, TlvTag tag)
    {
        w.StartList(tag);
        if (Endpoint is { } e) w.WriteUInt(TlvTag.ContextSpecific(TagEndpoint), e);
        if (Cluster is { } c) w.WriteUInt(TlvTag.ContextSpecific(TagCluster), c);
        if (Attribute is { } a) w.WriteUInt(TlvTag.ContextSpecific(TagAttribute), a);
        w.EndContainer();
    }

    public static AttributePath Read(ref TlvReader list)
    {
        ushort? endpoint = null;
        uint? cluster = null;
        uint? attribute = null;
        list.EnterContainer((ref TlvReader f) =>
        {
            switch (f.TagNumber)
            {
                case TagEndpoint: endpoint = (ushort)f.GetUInt(); break;
                case TagCluster: cluster = (uint)f.GetUInt(); break;
                case TagAttribute: attribute = (uint)f.GetUInt(); break;
            }
        });
        return new AttributePath(endpoint, cluster, attribute);
    }
}

/// <summary>
/// A command path (CommandPathIB, Matter Core Spec §10.6.6) — endpoint / cluster / command. Encoded as a
/// TLV <b>List</b> with context tags.
/// </summary>
public readonly record struct CommandPath(ushort Endpoint, uint Cluster, uint Command)
{
    private const int TagEndpoint = 0;
    private const int TagCluster = 1;
    private const int TagCommand = 2;

    public void Write(TlvWriter w, TlvTag tag)
    {
        w.StartList(tag);
        w.WriteUInt(TlvTag.ContextSpecific(TagEndpoint), Endpoint);
        w.WriteUInt(TlvTag.ContextSpecific(TagCluster), Cluster);
        w.WriteUInt(TlvTag.ContextSpecific(TagCommand), Command);
        w.EndContainer();
    }

    public static CommandPath Read(ref TlvReader list)
    {
        ushort endpoint = 0;
        uint cluster = 0, command = 0;
        list.EnterContainer((ref TlvReader f) =>
        {
            switch (f.TagNumber)
            {
                case TagEndpoint: endpoint = (ushort)f.GetUInt(); break;
                case TagCluster: cluster = (uint)f.GetUInt(); break;
                case TagCommand: command = (uint)f.GetUInt(); break;
            }
        });
        return new CommandPath(endpoint, cluster, command);
    }
}

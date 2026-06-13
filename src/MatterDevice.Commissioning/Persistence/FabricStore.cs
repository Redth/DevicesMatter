using System.Text.Json;
using MatterDevice.Core.Credentials;
using MatterDevice.Core.Crypto;

namespace MatterDevice.Commissioning.Persistence;

/// <summary>
/// Persists the device's commissioned fabrics so pairings survive restarts. Everything a fabric needs to
/// keep operating after a reboot is stored: the fabric/node ids, the root + NOC (+ optional ICAC) certs, the
/// IPK, and — critically — the <b>operational private key</b> (without it the device can't sign CASE Sigma3
/// and every controller would have to re-pair). Treat the persisted data as secret; it authenticates the
/// device on the fabric.
/// </summary>
public interface IFabricStore
{
    /// <summary>Replaces the persisted set with the current fabrics (called after any add/remove).</summary>
    void Save(IReadOnlyCollection<Fabric> fabrics);

    /// <summary>Loads the persisted fabrics (empty if none / unreadable).</summary>
    IReadOnlyList<Fabric> Load();
}

/// <summary>A JSON-file <see cref="IFabricStore"/> (written owner-only). Point it at a persistent volume.</summary>
public sealed class FileFabricStore : IFabricStore
{
    private readonly string _path;

    public FileFabricStore(string path)
    {
        _path = path;
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
    }

    public void Save(IReadOnlyCollection<Fabric> fabrics)
    {
        var dto = fabrics.Select(f => new PersistedFabric(
            f.FabricIndex, f.FabricId, f.NodeId,
            Convert.ToBase64String(f.RootCertificate.Encode()),
            Convert.ToBase64String(f.Noc.Encode()),
            f.Icac is null ? null : Convert.ToBase64String(f.Icac.Encode()),
            Convert.ToBase64String(f.OperationalKey.PrivateKey),
            Convert.ToBase64String(f.EpochIpk))).ToList();

        var json = JsonSerializer.Serialize(dto, new JsonSerializerOptions { WriteIndented = true });
        if (!OperatingSystem.IsWindows() && !File.Exists(_path))
        {
            using (File.Create(_path)) { }
            File.SetUnixFileMode(_path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        File.WriteAllText(_path, json);
    }

    public IReadOnlyList<Fabric> Load()
    {
        try
        {
            if (!File.Exists(_path)) return [];
            var dto = JsonSerializer.Deserialize<List<PersistedFabric>>(File.ReadAllText(_path)) ?? [];
            return dto.Select(d => new Fabric
            {
                FabricIndex = d.FabricIndex,
                FabricId = d.FabricId,
                NodeId = d.NodeId,
                RootCertificate = MatterCertificate.Decode(Convert.FromBase64String(d.RootCert)),
                Noc = MatterCertificate.Decode(Convert.FromBase64String(d.Noc)),
                Icac = d.Icac is null ? null : MatterCertificate.Decode(Convert.FromBase64String(d.Icac)),
                OperationalKey = P256KeyPair.FromPrivateKey(Convert.FromBase64String(d.OperationalKey)),
                EpochIpk = Convert.FromBase64String(d.EpochIpk),
            }).ToList();
        }
        catch
        {
            return []; // corrupt/unreadable → start fresh (device re-advertises as commissionable)
        }
    }

    private sealed record PersistedFabric(
        byte FabricIndex, ulong FabricId, ulong NodeId,
        string RootCert, string Noc, string? Icac, string OperationalKey, string EpochIpk);
}

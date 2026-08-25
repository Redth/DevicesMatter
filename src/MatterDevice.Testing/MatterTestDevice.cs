using System.Security.Cryptography;
using MatterDevice.Commissioning;
using MatterDevice.Commissioning.OperationalCredentials;
using MatterDevice.Core.Credentials;
using MatterDevice.Core.Crypto;
using MatterDevice.DataModel;
using MatterDevice.DataModel.InteractionModel;
using Microsoft.Extensions.Logging;

namespace MatterDevice.Testing;

/// <summary>
/// Builds a <see cref="MatterDeviceNode"/> wired for tests — throwaway attestation material and the
/// passcode <see cref="MatterTestController.DefaultPasscode"/>, so a test only has to supply its data
/// model. Pair with <see cref="MatterTestController.Commission"/>.
/// </summary>
public static class MatterTestDevice
{
    /// <summary>Creates a commissionable node over <paramref name="dataModel"/>.</summary>
    public static MatterDeviceNode Create(
        Node dataModel,
        uint passcode = MatterTestController.DefaultPasscode,
        CommandHandler? commandHandler = null,
        ILogger? logger = null) =>
        new(new MatterDeviceOptions
        {
            Passcode = passcode,
            PaseSalt = RandomNumberGenerator.GetBytes(16),
            Attestation = new DeviceAttestationProvider(
                P256KeyPair.Generate(),
                RandomNumberGenerator.GetBytes(64),
                RandomNumberGenerator.GetBytes(64),
                RandomNumberGenerator.GetBytes(128)),
            DataModel = dataModel,
            ApplicationCommandHandler = commandHandler,
        }, logger);
}

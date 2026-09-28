// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace PcmHacking
{
    /// <summary>
    /// Non-destructive read-only probe for the Allison AL5 TCM at VPW module 0x18.
    /// Identity blocks and the security seed are read at normal VPW speed.
    /// No security key is sent, and no code upload, erase, flash, or memory-write service is used.
    /// </summary>
    public sealed class AL5ReadOnlyProbe
    {
        public const byte TcmDeviceId = 0x18;
        // Verified offline against the previously observed AL5 pair:
        // seed 0x9CE5 -> key 0xBC08.  The key is calculated for characterization
        // only in this probe and is NOT sent to the TCM.
        public const int Al5KeyAlgorithm = 50;
        private readonly Vehicle vehicle;
        private readonly ILogger logger;

        public AL5ReadOnlyProbe(Vehicle vehicle, ILogger logger)
        {
            this.vehicle = vehicle ?? throw new ArgumentNullException(nameof(vehicle));
            this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public sealed class Result
        {
            public Dictionary<byte, byte[]> Blocks { get; } = new Dictionary<byte, byte[]>();
            public uint? HardwareId => UInt32(BlockId.HardwareID);
            public uint? CalibrationId => UInt32(BlockId.CalibrationID);
            public uint? OperatingSystemId => UInt32(BlockId.OperatingSystemID);

            private uint? UInt32(byte block)
            {
                if (!Blocks.TryGetValue(block, out byte[] data) || data == null || data.Length < 3)
                    return null;

                int start = data.Length >= 4 ? data.Length - 4 : 0;
                uint value = 0;
                for (int i = start; i < data.Length; i++)
                    value = (value << 8) | data[i];
                return value;
            }
        }

        public async Task<Response<Result>> Probe(CancellationToken cancellationToken)
        {
            Result result = new Result();

            // Start identity probing at normal VPW speed. Do not globally disable 4X;
            // the guarded transport check at the end may explicitly request it.
            await this.vehicle.SetDeviceTimeout(TimeoutScenario.ReadProperty);
            this.vehicle.ClearDeviceMessageQueue();

            byte[] blocks = new byte[]
            {
                BlockId.Vin1, BlockId.Vin2, BlockId.Vin3,
                BlockId.HardwareID,
                BlockId.Serial1, BlockId.Serial2, BlockId.Serial3,
                BlockId.CalibrationID,
                0x09,
                BlockId.OperatingSystemID,
                BlockId.EngineCalID,
                BlockId.SystemCalID,
                BlockId.BCC,
            };

            logger.AddUserMessage("AL5 read-only probe: target 0x18, normal VPW speed.");
            logger.AddUserMessage("No security key, upload, erase, flash, or memory-write services are used.");

            foreach (byte block in blocks)
            {
                if (cancellationToken.IsCancellationRequested)
                    return Response.Create(ResponseStatus.Cancelled, result);

                Response<byte[]> response = await ReadBlock(block, cancellationToken);
                if (response.Status == ResponseStatus.Success)
                {
                    result.Blocks[block] = response.Value;
                    logger.AddUserMessage(
                        string.Format("AL5 0x3C block 0x{0:X2}: {1}", block, BitConverter.ToString(response.Value)));
                }
                else
                {
                    logger.AddDebugMessage(
                        string.Format("AL5 0x3C block 0x{0:X2}: {1}", block, response.Status));
                }
            }

            if (!result.Blocks.ContainsKey(BlockId.OperatingSystemID))
            {
                logger.AddUserMessage("AL5 probe did not obtain OS block 0x0A.");
                return Response.Create(ResponseStatus.Error, result);
            }

            // Do not apply PCM block semantics to AL5 yet.  The first vehicle capture
            // proved that AL5 block 0x08 contains 15183963 (known hardware number) and
            // block 0x0A begins 00 E7 B0 ED = 15184109 (known OSID), with trailing bytes.
            // Preserve/log raw payloads until each AL5 block is independently identified.
            if (result.Blocks.TryGetValue(BlockId.OperatingSystemID, out byte[] osRaw))
                logger.AddUserMessage("AL5 raw OS block 0x0A: " + BitConverter.ToString(osRaw));
            if (result.Blocks.TryGetValue(BlockId.CalibrationID, out byte[] block08Raw))
                logger.AddUserMessage("AL5 raw block 0x08: " + BitConverter.ToString(block08Raw));

            logger.AddUserMessage("AL5 read-only identity probe complete.");

            // Vehicle testing showed that module 0x18 acknowledges the global VPW 4X
            // transition, but AL5 identity reads time out after the adapter switches to 4X.
            // Keep AL5 characterization at the reliable normal VPW rate for now.
            logger.AddUserMessage("AL5 retaining normal VPW 1X for security/read characterization.");

            Response<UInt16> seedResponse = await ReadSecuritySeed(cancellationToken);
            if (seedResponse.Status == ResponseStatus.Success)
            {
                UInt16 seed = seedResponse.Value;
                UInt16 predictedKey = KeyAlgorithm.GetKey(Al5KeyAlgorithm, seed);
                logger.AddUserMessage(
                    string.Format(
                        "AL5 security seed 0x{0:X4}; PCM Hammer algorithm #{1} predicts key 0x{2:X4} (not sent).",
                        seed, Al5KeyAlgorithm, predictedKey));
            }
            else
            {
                logger.AddUserMessage("AL5 security-seed probe: " + seedResponse.Status);
            }

            return Response.Create(ResponseStatus.Success, result);
        }

        private async Task<Response<UInt16>> ReadSecuritySeed(CancellationToken cancellationToken)
        {
            Message request = new Message(new byte[]
            {
                Priority.Physical0, TcmDeviceId, DeviceId.Tool, Mode.Seed, Submode.GetSeed
            });

            this.vehicle.ClearDeviceMessageQueue();
            if (!await this.vehicle.SendMessage(request))
                return Response.Create(ResponseStatus.Error, (UInt16)0);

            for (int attempt = 0; attempt < Vehicle.MaxReceiveAttempts; attempt++)
            {
                if (cancellationToken.IsCancellationRequested)
                    return Response.Create(ResponseStatus.Cancelled, (UInt16)0);

                Message message = await this.vehicle.ReceiveMessage();
                if (message == null)
                    continue;

                byte[] bytes = message.GetBytes();
                if (bytes.Length < 5)
                    continue;

                // Expected negative reply: 6C F0 18 7F 27 01 <NRC>
                if (bytes.Length >= 7 &&
                    bytes[0] == Priority.Physical0 &&
                    bytes[1] == DeviceId.Tool &&
                    bytes[2] == TcmDeviceId &&
                    bytes[3] == Mode.NegativeResponse &&
                    bytes[4] == Mode.Seed &&
                    bytes[5] == Submode.GetSeed)
                {
                    logger.AddUserMessage(
                        string.Format("AL5 seed request rejected, NRC 0x{0:X2}.", bytes[6]));
                    return Response.Create(ResponseStatus.Refused, (UInt16)0);
                }

                // Expected seed reply: 6C F0 18 67 01 <seedHi> <seedLo>
                if (bytes.Length >= 7 &&
                    bytes[0] == Priority.Physical0 &&
                    bytes[1] == DeviceId.Tool &&
                    bytes[2] == TcmDeviceId &&
                    bytes[3] == (Mode.Seed + Mode.Response) &&
                    bytes[4] == Submode.GetSeed)
                {
                    UInt16 seed = (UInt16)((bytes[5] << 8) | bytes[6]);
                    return Response.Create(ResponseStatus.Success, seed);
                }

                logger.AddDebugMessage("Ignoring unrelated AL5 security-probe message: " + message);
            }

            return Response.Create(ResponseStatus.Error, (UInt16)0);
        }

        private async Task<Response<byte[]>> ReadBlock(byte block, CancellationToken cancellationToken)
        {
            Message request = new Message(new byte[]
            {
                Priority.Physical0, TcmDeviceId, DeviceId.Tool, Mode.ReadBlock, block
            });

            this.vehicle.ClearDeviceMessageQueue();
            if (!await this.vehicle.SendMessage(request))
                return Response.Create(ResponseStatus.Error, new byte[0]);

            for (int attempt = 0; attempt < Vehicle.MaxReceiveAttempts; attempt++)
            {
                if (cancellationToken.IsCancellationRequested)
                    return Response.Create(ResponseStatus.Cancelled, new byte[0]);

                Message message = await this.vehicle.ReceiveMessage();
                if (message == null)
                    continue;

                byte[] bytes = message.GetBytes();
                if (bytes.Length < 5)
                    continue;

                // Negative response 7F 3C <block> <NRC>.  Log it immediately rather
                // than treating it as unrelated traffic and waiting through timeouts.
                if (bytes.Length >= 7 &&
                    bytes[0] == Priority.Physical0 &&
                    bytes[1] == DeviceId.Tool &&
                    bytes[2] == TcmDeviceId &&
                    bytes[3] == Mode.NegativeResponse &&
                    bytes[4] == Mode.ReadBlock &&
                    bytes[5] == block)
                {
                    logger.AddUserMessage(
                        string.Format("AL5 0x3C block 0x{0:X2} rejected, NRC 0x{1:X2}.", block, bytes[6]));
                    return Response.Create(ResponseStatus.Refused, new byte[0]);
                }

                // Expected: 6C F0 18 7C <block> <payload...>
                if (bytes[0] != Priority.Physical0 ||
                    bytes[1] != DeviceId.Tool ||
                    bytes[2] != TcmDeviceId ||
                    bytes[3] != (Mode.ReadBlock + Mode.Response) ||
                    bytes[4] != block)
                {
                    logger.AddDebugMessage("Ignoring unrelated AL5 probe message: " + message);
                    continue;
                }

                byte[] payload = new byte[bytes.Length - 5];
                Buffer.BlockCopy(bytes, 5, payload, 0, payload.Length);
                return Response.Create(ResponseStatus.Success, payload);
            }

            return Response.Create(ResponseStatus.Error, new byte[0]);
        }
    }
}

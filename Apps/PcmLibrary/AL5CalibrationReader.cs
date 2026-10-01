// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace PcmHacking
{
    /// <summary>
    /// Read-only AL5 calibration-segment reader using the stock TCM Mode 0x23 service.
    /// No security unlock, RAM upload, erase, flash, or memory-write service is used.
    /// </summary>
    public sealed class AL5CalibrationReader
    {
        public const byte TcmDeviceId = 0x18;
        public const int StartAddress = 0x08000;
        public const int EndAddressInclusive = 0x15FD7;
        public const int EndAddressExclusive = 0x15FD8;
        public const int Length = EndAddressExclusive - StartAddress;

        private readonly Vehicle vehicle;
        private readonly ILogger logger;

        public AL5CalibrationReader(Vehicle vehicle, ILogger logger)
        {
            this.vehicle = vehicle ?? throw new ArgumentNullException(nameof(vehicle));
            this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<Response<byte[]>> ReadCalibration(CancellationToken cancellationToken)
        {
            await this.vehicle.SetDeviceTimeout(TimeoutScenario.ReadProperty);
            this.vehicle.ClearDeviceMessageQueue();

            logger.AddUserMessage(
                string.Format(
                    "AL5 direct calibration read: 0x{0:X5}-0x{1:X5} ({2} bytes), Mode 0x23, VPW 1X.",
                    StartAddress, EndAddressInclusive, Length));
            logger.AddUserMessage(
                "Read-only path: no key, upload, erase, flash, or memory-write service is used.");

            // Prove that the third address byte is honored before crossing 0xFFFF.
            // The offline-verified D5196 header at 0x158A8 is 00 11 00 09.
            Response<byte[]> highAddressProbe = await ReadDword(0x158A8, cancellationToken);
            if (highAddressProbe.Status != ResponseStatus.Success)
            {
                logger.AddUserMessage(
                    "AL5 high-address preflight failed; full calibration read was not started.");
                return Response.Create(highAddressProbe.Status, new byte[0]);
            }

            byte[] expectedHighAddress = { 0x00, 0x11, 0x00, 0x09 };
            if (!Equal4(highAddressProbe.Value, expectedHighAddress))
            {
                logger.AddUserMessage(
                    "AL5 high-address preflight returned unexpected data at 0x158A8: " +
                    BitConverter.ToString(highAddressProbe.Value));
                logger.AddUserMessage(
                    "Aborting because 24-bit address handling has not been proven.");
                return Response.Create(ResponseStatus.Unverified, new byte[0]);
            }

            logger.AddUserMessage(
                "AL5 24-bit Mode 0x23 addressing confirmed at 0x158A8 (00-11-00-09).");

            byte[] image = new byte[Length];
            int retries = 0;

            for (int address = StartAddress; address < EndAddressExclusive; address += 4)
            {
                if (cancellationToken.IsCancellationRequested)
                    return Response.Create(ResponseStatus.Cancelled, image);

                Response<byte[]> response = await ReadDword(address, cancellationToken);
                if (response.Status != ResponseStatus.Success || response.Value.Length != 4)
                {
                    logger.AddUserMessage(
                        string.Format("AL5 calibration read failed at 0x{0:X5}: {1}", address, response.Status));
                    return Response.Create(response.Status, image);
                }

                Buffer.BlockCopy(response.Value, 0, image, address - StartAddress, 4);
                retries += response.RetryCount;

                int completed = (address - StartAddress) + 4;
                if ((completed % 0x1000) == 0 || completed == Length)
                {
                    logger.AddUserMessage(
                        string.Format(
                            "AL5 calibration read {0}/{1} bytes ({2:F1}%).",
                            completed, Length, completed * 100.0 / Length));
                }
            }

            if (!ValidateKnownAnchors(image))
            {
                logger.AddUserMessage(
                    "AL5 calibration read completed, but one or more known anchors did not validate.");
                return Response.Create(ResponseStatus.Unverified, image);
            }

            ushort sum = BigEndianWordSum(image);
            if (sum != 0)
            {
                logger.AddUserMessage(
                    string.Format(
                        "AL5 calibration segment BE16 checksum invariant failed: 0x{0:X4}.",
                        sum));
                return Response.Create(ResponseStatus.Unverified, image);
            }

            string sha256;
            using (SHA256 hash = SHA256.Create())
            {
                sha256 = BitConverter.ToString(hash.ComputeHash(image)).Replace("-", "").ToLowerInvariant();
            }

            logger.AddUserMessage("AL5 calibration anchors validated.");
            logger.AddUserMessage("AL5 calibration BE16 word-sum checksum = 0x0000.");
            logger.AddUserMessage("AL5 calibration SHA256: " + sha256);
            logger.AddUserMessage("AL5 direct calibration read complete.");

            return new Response<byte[]>(ResponseStatus.Success, image, retries);
        }

        private async Task<Response<byte[]>> ReadDword(int address, CancellationToken cancellationToken)
        {
            const int maxSendAttempts = 3;
            int retries = 0;

            for (int sendAttempt = 1; sendAttempt <= maxSendAttempts; sendAttempt++)
            {
                Message request = new Message(new byte[]
                {
                    Priority.Block, TcmDeviceId, DeviceId.Tool, Mode.GetRam,
                    (byte)(address >> 16), (byte)(address >> 8), (byte)address, 0x01
                });

                this.vehicle.ClearDeviceMessageQueue();
                if (!await this.vehicle.SendMessage(request))
                {
                    retries++;
                    continue;
                }

                for (int receiveAttempt = 0; receiveAttempt < Vehicle.MaxReceiveAttempts; receiveAttempt++)
                {
                    if (cancellationToken.IsCancellationRequested)
                        return new Response<byte[]>(ResponseStatus.Cancelled, new byte[0], retries);

                    Message message = await this.vehicle.ReceiveMessage();
                    if (message == null)
                        continue;

                    byte[] bytes = message.GetBytes();
                    if (bytes.Length < 5)
                        continue;

                    // Negative response to Mode 0x23.
                    if (bytes[0] == Priority.Physical0 &&
                        bytes[1] == DeviceId.Tool &&
                        bytes[2] == TcmDeviceId &&
                        bytes[3] == Mode.NegativeResponse &&
                        bytes[4] == Mode.GetRam)
                    {
                        logger.AddUserMessage(
                            string.Format(
                                "AL5 Mode 0x23 rejected at 0x{0:X5}: {1}",
                                address, BitConverter.ToString(bytes)));
                        return new Response<byte[]>(ResponseStatus.Refused, new byte[0], retries);
                    }

                    // Verified live response shape is:
                    // 6C F0 18 63 <addr-low16-hi> <addr-low16-lo> <4 data bytes>
                    // For safety, require the echoed low 16 address bits to match and
                    // take the final four bytes as data.  This also tolerates a future
                    // AL5 response that includes the high address byte before the echo.
                    if (bytes.Length >= 10 &&
                        bytes[0] == Priority.Physical0 &&
                        bytes[1] == DeviceId.Tool &&
                        bytes[2] == TcmDeviceId &&
                        bytes[3] == (Mode.GetRam + Mode.Response))
                    {
                        bool low16Echo =
                            bytes[4] == (byte)(address >> 8) &&
                            bytes[5] == (byte)address;

                        bool full24Echo =
                            bytes.Length >= 11 &&
                            bytes[4] == (byte)(address >> 16) &&
                            bytes[5] == (byte)(address >> 8) &&
                            bytes[6] == (byte)address;

                        if (low16Echo || full24Echo)
                        {
                            byte[] data = new byte[4];
                            Buffer.BlockCopy(bytes, bytes.Length - 4, data, 0, 4);
                            return new Response<byte[]>(ResponseStatus.Success, data, retries);
                        }
                    }

                    logger.AddDebugMessage("Ignoring unrelated AL5 Mode-0x23 message: " + message);
                }

                retries++;
            }

            return new Response<byte[]>(ResponseStatus.Error, new byte[0], retries);
        }

        private bool ValidateKnownAnchors(byte[] image)
        {
            // Transmission calibration ID 15183960 at 0x08024.
            byte[] calId = { 0x00, 0xE7, 0xB0, 0x58 };
            if (!Matches(image, 0x08024, calId))
                return false;

            // Reverse, 1st, 2nd, 3rd, 4th, 5th gear ratio raw words.
            byte[] gears =
            {
                0x11, 0xF7, 0x0C, 0x68, 0x07, 0x3E,
                0x05, 0xA0, 0x04, 0x00, 0x02, 0xD9
            };
            if (!Matches(image, 0x0A996, gears))
                return false;

            // D5196 dimensions: 17 rows x 9 columns.
            byte[] d5196Header = { 0x00, 0x11, 0x00, 0x09 };
            return Matches(image, 0x158A8, d5196Header);
        }

        private bool Matches(byte[] image, int absoluteAddress, byte[] expected)
        {
            int offset = absoluteAddress - StartAddress;
            if (offset < 0 || offset + expected.Length > image.Length)
                return false;

            for (int i = 0; i < expected.Length; i++)
            {
                if (image[offset + i] != expected[i])
                    return false;
            }

            return true;
        }

        private static bool Equal4(byte[] actual, byte[] expected)
        {
            if (actual == null || expected == null || actual.Length != 4 || expected.Length != 4)
                return false;

            for (int i = 0; i < 4; i++)
            {
                if (actual[i] != expected[i])
                    return false;
            }

            return true;
        }

        private static ushort BigEndianWordSum(byte[] bytes)
        {
            uint sum = 0;
            for (int i = 0; i + 1 < bytes.Length; i += 2)
                sum = (sum + (uint)((bytes[i] << 8) | bytes[i + 1])) & 0xFFFF;

            return (ushort)sum;
        }
    }
}

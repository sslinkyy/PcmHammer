// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Threading;
using System.Threading.Tasks;

namespace PcmHacking
{
    /// <summary>
    /// Read-only lower-RAM survey for the E54 using PCM Hammer's existing E54 read kernel.
    ///
    /// Stock E54 OS 15189044 rejects diagnostic Mode 0x23 arbitrary RAM reads,
    /// so this helper temporarily runs the existing read kernel and uses Mode 0x35.
    ///
    /// The standard E54 kernel loads at 0xFF9100 and moves its stack to 0xFFB800.
    /// To avoid reading the survey kernel itself, this first-stage survey is restricted
    /// to 0xFF8000-0xFF90FF.
    /// </summary>
    public sealed class E54RamSurvey
    {
        public const int StartAddress = 0xFF8000;
        public const int EndAddressInclusive = 0xFF90FF;
        public const int Length = EndAddressInclusive - StartAddress + 1;

        private readonly Vehicle vehicle;
        private readonly ILogger logger;
        private readonly Protocol protocol;

        public E54RamSurvey(Vehicle vehicle, ILogger logger)
        {
            this.vehicle = vehicle ?? throw new ArgumentNullException(nameof(vehicle));
            this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
            this.protocol = new Protocol();
        }

        /// <summary>
        /// Upload the normal E54 read kernel, capture only the lower safe survey window,
        /// and always return the PCM to its factory OS in a finally block.
        /// </summary>
        public async Task<Response<byte[]>> ReadLowerWindow(CancellationToken cancellationToken)
        {
            OSIDInfo info = new OSIDInfo(PcmType.E54);

            try
            {
                this.logger.AddUserMessage(
                    string.Format(
                        "E54 RAM survey: 0x{0:X6}-0x{1:X6} ({2} bytes).",
                        StartAddress,
                        EndAddressInclusive,
                        Length));

                Response<uint> osidResponse =
                    await this.vehicle.QueryOperatingSystemId(cancellationToken);

                if (osidResponse.Status != ResponseStatus.Success)
                {
                    this.logger.AddUserMessage(
                        "Unable to query OSID before E54 RAM survey: " +
                        osidResponse.Status);
                    return Response.Create(
                        osidResponse.Status,
                        new byte[0]);
                }

                OSIDInfo connectedInfo = new OSIDInfo(osidResponse.Value);
                if (connectedInfo.HardwareType != PcmType.E54)
                {
                    this.logger.AddUserMessage(
                        "RAM survey aborted: connected PCM is " +
                        connectedInfo.HardwareType +
                        ", not E54.");
                    return Response.Create(
                        ResponseStatus.Error,
                        new byte[0]);
                }

                info = connectedInfo;

                this.logger.AddUserMessage(
                    "E54 RAM survey OSID: " + osidResponse.Value);

                await this.vehicle.SuppressChatter();

                bool unlocked = await this.vehicle.UnlockEcu(info.KeyAlgorithm);
                if (!unlocked)
                {
                    this.logger.AddUserMessage(
                        "Unable to unlock E54 for RAM survey.");
                    return Response.Create(
                        ResponseStatus.Error,
                        new byte[0]);
                }

                await this.vehicle.ForceSendToolPresentNotification();
                this.vehicle.ClearDeviceMessageQueue();

                if (this.vehicle.Enable4xReadWrite)
                {
                    if (!await this.vehicle.VehicleSetVPW4x(
                        info,
                        VpwSpeed.FourX))
                    {
                        this.logger.AddUserMessage(
                            "Unable to switch to VPW 4X for E54 RAM survey.");
                        return Response.Create(
                            ResponseStatus.Error,
                            new byte[0]);
                    }
                }
                else
                {
                    this.logger.AddUserMessage(
                        "4X communications disabled by configuration.");
                }

                await this.vehicle.SendToolPresentNotification();

                Response<byte[]> kernelResponse =
                    await this.vehicle.LoadKernelFromFile(info.KernelFileName);

                if (kernelResponse.Status != ResponseStatus.Success)
                {
                    this.logger.AddUserMessage(
                        "Failed to load E54 read kernel from file.");
                    return Response.Create(
                        kernelResponse.Status,
                        new byte[0]);
                }

                if (cancellationToken.IsCancellationRequested)
                {
                    return Response.Create(
                        ResponseStatus.Cancelled,
                        new byte[0]);
                }

                await this.vehicle.SendToolPresentNotification();

                if (!await this.vehicle.PCMExecute(
                    info,
                    kernelResponse.Value,
                    cancellationToken))
                {
                    this.logger.AddUserMessage(
                        "Failed to upload E54 read kernel for RAM survey.");
                    return Response.Create(
                        cancellationToken.IsCancellationRequested
                            ? ResponseStatus.Cancelled
                            : ResponseStatus.Error,
                        new byte[0]);
                }

                this.logger.AddUserMessage(
                    "E54 read kernel uploaded. Reading lower RAM window...");

                await this.vehicle.SetDeviceTimeout(
                    TimeoutScenario.ReadMemoryBlock);

                byte[] output = new byte[Length];

                int blockSize = this.vehicle.DeviceMaxReceiveSize - 12;
                if (blockSize > info.KernelMaxBlockSize)
                {
                    blockSize = info.KernelMaxBlockSize;
                }

                // Keep this diagnostic survey deliberately modest.
                if (blockSize > 0x100)
                {
                    blockSize = 0x100;
                }

                if (blockSize < 1)
                {
                    this.logger.AddUserMessage(
                        "RAM survey block size is invalid.");
                    return Response.Create(
                        ResponseStatus.Error,
                        new byte[0]);
                }

                int offset = 0;
                while (offset < output.Length)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        return Response.Create(
                            ResponseStatus.Cancelled,
                            new byte[0]);
                    }

                    await this.vehicle.ForceSendToolPresentNotification();

                    int count = Math.Min(
                        blockSize,
                        output.Length - offset);

                    int address = StartAddress + offset;

                    Response<byte[]> readResponse =
                        await this.vehicle.ReadMemory(
                            () => this.protocol.CreateReadRequest(
                                address,
                                count),
                            message => this.protocol.ParsePayload(
                                message,
                                count,
                                address),
                            cancellationToken);

                    if (readResponse.Status != ResponseStatus.Success)
                    {
                        this.logger.AddUserMessage(
                            string.Format(
                                "RAM survey failed at 0x{0:X6}: {1}.",
                                address,
                                readResponse.Status));

                        return Response.Create(
                            readResponse.Status,
                            new byte[0]);
                    }

                    if (readResponse.Value.Length != count)
                    {
                        this.logger.AddUserMessage(
                            string.Format(
                                "RAM survey expected {0} bytes at 0x{1:X6}, received {2}.",
                                count,
                                address,
                                readResponse.Value.Length));

                        return Response.Create(
                            ResponseStatus.Truncated,
                            new byte[0]);
                    }

                    Buffer.BlockCopy(
                        readResponse.Value,
                        0,
                        output,
                        offset,
                        count);

                    offset += count;

                    this.logger.StatusUpdateActivity(
                        string.Format(
                            "Reading E54 RAM 0x{0:X6}",
                            address));

                    this.logger.StatusUpdatePercentDone(
                        string.Format(
                            "{0}%",
                            offset * 100 / output.Length));

                    this.logger.StatusUpdateProgressBar(
                        (double)offset / output.Length,
                        true);
                }

                this.logger.AddUserMessage(
                    "E54 lower RAM survey complete.");

                return Response.Create(
                    ResponseStatus.Success,
                    output);
            }
            catch (Exception exception)
            {
                this.logger.AddUserMessage(
                    "E54 RAM survey failed: " +
                    exception.Message);

                this.logger.AddDebugMessage(
                    exception.ToString());

                return Response.Create(
                    ResponseStatus.Error,
                    new byte[0]);
            }
            finally
            {
                this.logger.AddUserMessage(
                    "Returning PCM to normal operation.");

                await this.vehicle.Cleanup();
                this.logger.StatusUpdateReset();
            }
        }
    }
}

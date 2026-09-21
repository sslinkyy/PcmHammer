// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace PcmHacking
{
    public enum E54RamCanaryOutcome
    {
        Error = 0,
        Cancelled,
        OriginalWindowNotZero,
        Survived,
        ClearedDuringRestartOrRuntime,
        ChangedByFactoryRuntime,
    }

    /// <summary>
    /// Bench-only canary test for the provisional E54 iMob RAM candidate.
    ///
    /// The test never accepts an arbitrary RAM address or arbitrary payload.
    /// The custom E54 kernel can only write "IMOB" to 0xFF88C0 and can only
    /// clear those same four bytes with a separate guarded command.
    ///
    /// This is evidence gathering only. A surviving canary does not by itself
    /// freeze the RAM allocation.
    /// </summary>
    public sealed class E54RamCanaryTest
    {
        public const int ProvisionalStart = 0xFF88B0;
        public const int ProvisionalLength = 0x20;
        public const int CanaryAddress = 0xFF88C0;
        public const int CanaryOffset = CanaryAddress - ProvisionalStart;

        private static readonly byte[] Canary = new byte[]
        {
            0x49, 0x4D, 0x4F, 0x42, // "IMOB"
        };

        private readonly Vehicle vehicle;
        private readonly ILogger logger;
        private readonly Protocol protocol;

        private bool kernelRunning;

        public E54RamCanaryTest(Vehicle vehicle, ILogger logger)
        {
            this.vehicle = vehicle ?? throw new ArgumentNullException(nameof(vehicle));
            this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
            this.protocol = new Protocol();
        }

        public async Task<E54RamCanaryOutcome> Run(CancellationToken cancellationToken)
        {
            try
            {
                this.logger.AddUserMessage(
                    "Starting BENCH-ONLY E54 RAM canary test.");
                this.logger.AddUserMessage(
                    "Provisional window: 0xFF88B0-0xFF88CF; canary: 0xFF88C0-0xFF88C3.");

                if (!await this.StartKernel(cancellationToken))
                {
                    return cancellationToken.IsCancellationRequested
                        ? E54RamCanaryOutcome.Cancelled
                        : E54RamCanaryOutcome.Error;
                }

                Response<byte[]> before =
                    await this.ReadWindow(cancellationToken);

                if (before.Status != ResponseStatus.Success)
                {
                    return E54RamCanaryOutcome.Error;
                }

                this.logger.AddUserMessage(
                    "Pre-test RAM window: " + ToHex(before.Value));

                if (before.Value.Any(b => b != 0))
                {
                    this.logger.AddUserMessage(
                        "ABORT: provisional RAM window is not all zero before the canary write.");
                    return E54RamCanaryOutcome.OriginalWindowNotZero;
                }

                Response<byte> setResponse =
                    await this.SendCanarySet(cancellationToken);

                if (setResponse.Status != ResponseStatus.Success ||
                    setResponse.Value != 0)
                {
                    this.logger.AddUserMessage(
                        "Canary SET command was not accepted.");
                    return E54RamCanaryOutcome.Error;
                }

                Response<byte[]> armed =
                    await this.ReadWindow(cancellationToken);

                if (armed.Status != ResponseStatus.Success)
                {
                    return E54RamCanaryOutcome.Error;
                }

                if (!WindowIsExpectedCanary(armed.Value))
                {
                    this.logger.AddUserMessage(
                        "Canary verification failed immediately after SET: " +
                        ToHex(armed.Value));
                    return E54RamCanaryOutcome.Error;
                }

                this.logger.AddUserMessage(
                    "Canary armed successfully: " + ToHex(armed.Value));

                // Return to the factory operating system. This intentionally includes
                // the normal kernel exit/reset path, so a cleared canary can indicate
                // startup initialization as well as runtime activity.
                await this.StopKernel();

                if (!await this.WaitForFactoryOs(cancellationToken))
                {
                    return cancellationToken.IsCancellationRequested
                        ? E54RamCanaryOutcome.Cancelled
                        : E54RamCanaryOutcome.Error;
                }

                this.logger.AddUserMessage(
                    "Factory OS is responding. Exercising normal diagnostic activity for 30 seconds.");

                for (int pass = 1; pass <= 6; pass++)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        return E54RamCanaryOutcome.Cancelled;
                    }

                    Response<uint> osid =
                        await this.vehicle.QueryOperatingSystemId(cancellationToken);

                    this.logger.AddUserMessage(
                        string.Format(
                            "Factory activity pass {0}/6: OSID status {1}{2}",
                            pass,
                            osid.Status,
                            osid.Status == ResponseStatus.Success
                                ? ", value " + osid.Value
                                : string.Empty));

                    await Task.Delay(5000, cancellationToken);
                }

                if (!await this.StartKernel(cancellationToken))
                {
                    return cancellationToken.IsCancellationRequested
                        ? E54RamCanaryOutcome.Cancelled
                        : E54RamCanaryOutcome.Error;
                }

                Response<byte[]> after =
                    await this.ReadWindow(cancellationToken);

                if (after.Status != ResponseStatus.Success)
                {
                    return E54RamCanaryOutcome.Error;
                }

                this.logger.AddUserMessage(
                    "Post-runtime RAM window: " + ToHex(after.Value));

                bool neighborChanged = false;
                for (int i = 0; i < after.Value.Length; i++)
                {
                    if (i >= CanaryOffset && i < CanaryOffset + Canary.Length)
                    {
                        continue;
                    }

                    if (after.Value[i] != 0)
                    {
                        neighborChanged = true;
                        break;
                    }
                }

                byte[] observedCanary = new byte[Canary.Length];
                Buffer.BlockCopy(
                    after.Value,
                    CanaryOffset,
                    observedCanary,
                    0,
                    observedCanary.Length);

                if (neighborChanged)
                {
                    this.logger.AddUserMessage(
                        "RESULT: factory runtime changed bytes elsewhere inside the provisional 32-byte window.");
                    this.logger.AddUserMessage(
                        "Do not allocate this provisional block.");
                    return E54RamCanaryOutcome.ChangedByFactoryRuntime;
                }

                if (observedCanary.SequenceEqual(Canary))
                {
                    this.logger.AddUserMessage(
                        "RESULT: canary survived factory restart plus 30 seconds of diagnostic activity.");

                    Response<byte> clearResponse =
                        await this.SendCanaryClear(cancellationToken);

                    if (clearResponse.Status != ResponseStatus.Success ||
                        clearResponse.Value != 0)
                    {
                        this.logger.AddUserMessage(
                            "WARNING: canary survived but CLEAR was not acknowledged. Power-cycle the bench PCM.");
                        return E54RamCanaryOutcome.Error;
                    }

                    Response<byte[]> cleared =
                        await this.ReadWindow(cancellationToken);

                    if (cleared.Status != ResponseStatus.Success ||
                        cleared.Value.Any(b => b != 0))
                    {
                        this.logger.AddUserMessage(
                            "WARNING: canary CLEAR did not restore the full provisional window to zero. Power-cycle the bench PCM.");
                        return E54RamCanaryOutcome.Error;
                    }

                    this.logger.AddUserMessage(
                        "Canary cleared and zero window verified.");
                    return E54RamCanaryOutcome.Survived;
                }

                if (observedCanary.All(b => b == 0))
                {
                    this.logger.AddUserMessage(
                        "RESULT: canary was cleared during factory restart or subsequent runtime.");
                    this.logger.AddUserMessage(
                        "This is INCONCLUSIVE for free-space: startup initialization alone could explain the clear.");
                    return E54RamCanaryOutcome.ClearedDuringRestartOrRuntime;
                }

                this.logger.AddUserMessage(
                    "RESULT: factory runtime changed the canary bytes to " +
                    ToHex(observedCanary) + ".");
                this.logger.AddUserMessage(
                    "Do not allocate this provisional block. Power-cycle the bench PCM.");
                return E54RamCanaryOutcome.ChangedByFactoryRuntime;
            }
            catch (TaskCanceledException)
            {
                return E54RamCanaryOutcome.Cancelled;
            }
            catch (Exception exception)
            {
                this.logger.AddUserMessage(
                    "E54 RAM canary test failed: " + exception.Message);
                this.logger.AddDebugMessage(exception.ToString());
                return E54RamCanaryOutcome.Error;
            }
            finally
            {
                if (this.kernelRunning)
                {
                    await this.StopKernel();
                }

                this.logger.StatusUpdateReset();
            }
        }

        private async Task<bool> StartKernel(CancellationToken cancellationToken)
        {
            Response<uint> osidResponse =
                await this.vehicle.QueryOperatingSystemId(cancellationToken);

            if (osidResponse.Status != ResponseStatus.Success)
            {
                this.logger.AddUserMessage(
                    "Unable to query OSID before E54 canary phase: " +
                    osidResponse.Status);
                return false;
            }

            OSIDInfo info = new OSIDInfo(osidResponse.Value);
            if (info.HardwareType != PcmType.E54)
            {
                this.logger.AddUserMessage(
                    "Canary test aborted: connected PCM is " +
                    info.HardwareType + ", not E54.");
                return false;
            }

            await this.vehicle.SuppressChatter();

            if (!await this.vehicle.UnlockEcu(info.KeyAlgorithm))
            {
                this.logger.AddUserMessage(
                    "Unable to unlock E54 for canary phase.");
                return false;
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
                        "Unable to switch to VPW 4X for canary phase.");
                    return false;
                }
            }

            Response<byte[]> kernel =
                await this.vehicle.LoadKernelFromFile(info.KernelFileName);

            if (kernel.Status != ResponseStatus.Success)
            {
                this.logger.AddUserMessage(
                    "Unable to load Kernel-E54.bin for canary phase.");
                return false;
            }

            await this.vehicle.SendToolPresentNotification();

            if (!await this.vehicle.PCMExecute(
                info,
                kernel.Value,
                cancellationToken))
            {
                this.logger.AddUserMessage(
                    "Unable to upload E54 canary kernel.");
                return false;
            }

            this.kernelRunning = true;
            await this.vehicle.SetDeviceTimeout(
                TimeoutScenario.ReadMemoryBlock);

            return true;
        }

        private async Task StopKernel()
        {
            if (!this.kernelRunning)
            {
                return;
            }

            this.logger.AddUserMessage(
                "Returning PCM to factory operating system.");
            await this.vehicle.Cleanup();
            this.kernelRunning = false;
        }

        private async Task<bool> WaitForFactoryOs(CancellationToken cancellationToken)
        {
            for (int attempt = 1; attempt <= 30; attempt++)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    return false;
                }

                await Task.Delay(500, cancellationToken);

                Response<uint> response =
                    await this.vehicle.QueryOperatingSystemId(cancellationToken);

                if (response.Status == ResponseStatus.Success &&
                    new OSIDInfo(response.Value).HardwareType == PcmType.E54)
                {
                    this.logger.AddUserMessage(
                        "Factory OS returned after " + attempt + " polling attempts.");
                    return true;
                }
            }

            this.logger.AddUserMessage(
                "Factory OS did not resume within the canary-test timeout.");
            return false;
        }

        private async Task<Response<byte[]>> ReadWindow(
            CancellationToken cancellationToken)
        {
            await this.vehicle.ForceSendToolPresentNotification();

            return await this.vehicle.ReadMemory(
                () => this.protocol.CreateReadRequest(
                    ProvisionalStart,
                    ProvisionalLength),
                message => this.protocol.ParsePayload(
                    message,
                    ProvisionalLength,
                    ProvisionalStart),
                cancellationToken);
        }

        private async Task<Response<byte>> SendCanarySet(
            CancellationToken cancellationToken)
        {
            await this.vehicle.SetDeviceTimeout(
                TimeoutScenario.ReadProperty);

            Query<byte> query = this.vehicle.CreateQuery(
                this.protocol.CreateE54RamCanarySetRequest,
                this.protocol.ParseE54RamCanarySetResponse,
                cancellationToken);

            return await query.Execute();
        }

        private async Task<Response<byte>> SendCanaryClear(
            CancellationToken cancellationToken)
        {
            await this.vehicle.SetDeviceTimeout(
                TimeoutScenario.ReadProperty);

            Query<byte> query = this.vehicle.CreateQuery(
                this.protocol.CreateE54RamCanaryClearRequest,
                this.protocol.ParseE54RamCanaryClearResponse,
                cancellationToken);

            return await query.Execute();
        }

        private static bool WindowIsExpectedCanary(byte[] window)
        {
            if (window == null || window.Length != ProvisionalLength)
            {
                return false;
            }

            for (int i = 0; i < window.Length; i++)
            {
                if (i >= CanaryOffset && i < CanaryOffset + Canary.Length)
                {
                    if (window[i] != Canary[i - CanaryOffset])
                    {
                        return false;
                    }
                }
                else if (window[i] != 0)
                {
                    return false;
                }
            }

            return true;
        }

        private static string ToHex(byte[] value)
        {
            return value == null
                ? "<null>"
                : BitConverter.ToString(value).Replace("-", " ");
        }
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// Managed, bounded E54 RAM-kernel qualification. The caller owns AutoCal setup,
// native transport lifetime, journaling and physical bench power. No full read,
// flash identification, erase/program, DTC clear or speed transition is allowed.
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using PcmHacking;

internal enum AutoCalKernelProbeStage
{
    NotStarted, InitialIdentity, SuppressChatter, Unlock, RamUpload,
    KernelVersion, ExitKernel, PostExitIdentity, Complete, RamCopyObserved
}

internal sealed class AutoCalKernelProbeResult
{
    public bool Success { get; internal set; }
    public bool Cancelled { get; internal set; }
    public AutoCalKernelProbeStage Stage { get; internal set; }
    public string? Error { get; internal set; }
    public bool InitialIdentityVerified { get; internal set; }
    public bool KernelVersionVerified { get; internal set; }
    public ulong KernelVersion { get; internal set; }
    public bool ExitAcknowledged { get; internal set; }
    public bool PostExitIdentityVerified { get; internal set; }
    public bool RamExecuteSubmitted { get; internal set; }
    public bool ObservationOnly { get; internal set; }
    // This means the stock-ROM response was observed. Its opaque suffix is
    // retained by policy; neither the copied bytes nor execution are verified.
    public bool RamCopyReplyObserved { get; internal set; }
    public bool RamCopyBytesVerified => false;
    public bool BenchPowerCycleRequired { get; internal set; }
    public int VpwTransmissions { get; internal set; }
    public int VpwReceivedFrames { get; internal set; }
    public int RetainedQueueClearRequests { get; internal set; }
    public bool FlashWriteEnabled => false;
    public bool PhysicalSpeedMeasured => false;
    public bool OwnsAutoCalTransport => false;
}

internal sealed class AutoCalKernelProbeSession
{
    private readonly AutoCalDevice inner;
    private readonly ILogger logger;
    private readonly AutoCalKernelProbePolicy policy;
    private readonly CancellationToken cancellation;
    private readonly bool copyOnly;
    private int started;

    public AutoCalKernelProbeSession(AutoCalDevice device, ILogger logger,
        AutoCalKernelProbePolicy policy, CancellationToken cancellationToken, bool copyOnly = false)
    {
        inner = device ?? throw new ArgumentNullException(nameof(device));
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
        this.policy = policy ?? throw new ArgumentNullException(nameof(policy));
        cancellation = cancellationToken;
        this.copyOnly = copyOnly;
    }

    public async Task<AutoCalKernelProbeResult> RunAsync()
    {
        // A session is never retried with a partially advanced wire policy.
        if (Interlocked.Exchange(ref started, 1) != 0)
            throw new InvalidOperationException("The bounded kernel probe was already attempted.");
        var result = new AutoCalKernelProbeResult { ObservationOnly = copyOnly };
        var guarded = new GuardedDevice(inner, logger, policy, cancellation);
        try
        {
            cancellation.ThrowIfCancellationRequested();
            if (!inner.AdapterSetupAccepted)
                throw new InvalidOperationException("The caller must finish the ordinary identification adapter setup first.");
            if (policy.IsInitialIdentityVerified || policy.IsKernelVerified || policy.IsExitConfirmed)
                throw new InvalidOperationException("The kernel probe requires a new, unused policy.");
            if (inner.ReceivedMessageCount != 0 || inner.Channel.BufferedByteCount != 0 || inner.Channel.PendingByteCount != 0)
                throw new InvalidOperationException("Pending bytes exist before the kernel probe; they were preserved, not purged.");

            var protocol = new Protocol();
            var notifier = new ToolPresentNotifier(guarded, protocol, logger);
            var vehicle = new Vehicle(guarded, protocol, logger, notifier, string.Empty)
            {
                Enable4xReadWrite = false,
                // Version is queried below with exactly one attempt.
                ReportKernelID = false
            };
            var info = new OSIDInfo(AutoCalKernelProbePolicy.ExpectedOperatingSystem);
            if (info.OSID != AutoCalKernelProbePolicy.ExpectedOperatingSystem || info.HardwareType != PcmType.E54
                || info.LoaderRequired || info.KernelBaseAddress != 0xFF9100 || info.KeyAlgorithm != 54
                || info.ImageBaseAddress != 0 || info.ImageSize != 524288)
                throw new InvalidDataException("PcmHammer's E54 profile differs from the fixed RAM-kernel plan.");

            result.Stage = AutoCalKernelProbeStage.InitialIdentity;
            await FixedIdentity(guarded, protocol, () => policy.IsInitialIdentityVerified).ConfigureAwait(false);

            result.Stage = AutoCalKernelProbeStage.SuppressChatter;
            await guarded.SetTimeout(TimeoutScenario.Minimum).ConfigureAwait(false);
            await vehicle.SuppressChatter().ConfigureAwait(false);
            cancellation.ThrowIfCancellationRequested();

            result.Stage = AutoCalKernelProbeStage.Unlock;
            if (!await vehicle.UnlockEcu(54).ConfigureAwait(false))
                throw new InvalidDataException("The fixed E54 security exchange did not grant RAM upload access.");
            cancellation.ThrowIfCancellationRequested();

            result.Stage = AutoCalKernelProbeStage.RamUpload;
            if (copyOnly)
            {
                // First physical RAM qualification stops after the high-address
                // fragment. The stock Copy ACK suffix has not been established;
                // observing it must never authorize executing the whole kernel.
                var permission = new Query<bool>(guarded,
                    () => protocol.CreateUploadRequest(info, AutoCalKernelProbePolicy.ExpectedKernelLength),
                    reply => protocol.ParseUploadPermissionResponse(info, reply), logger, cancellation, notifier);
                Response<bool> permissionResult = await permission.Execute().ConfigureAwait(false);
                if (permissionResult.Status != ResponseStatus.Success || !permissionResult.Value)
                    throw new InvalidDataException("The fixed E54 RAM-copy upload permission was not granted.");
                cancellation.ThrowIfCancellationRequested();
                await guarded.SetTimeout(TimeoutScenario.SendKernel).ConfigureAwait(false);
                Response<bool> copied = await vehicle.WritePayload(new Message(policy.UploadMessages[0]), cancellation).ConfigureAwait(false);
                cancellation.ThrowIfCancellationRequested();
                if (copied.Status != ResponseStatus.Success || !copied.Value || policy.RamCopyAcknowledgement == null)
                    throw new InvalidDataException("No correlated stock-ROM RAM-copy response was observed.");
                result.Stage = AutoCalKernelProbeStage.RamCopyObserved;
                result.Success = true; // Observation completed; not byte-copy verification.
                return result;
            }
            if (!await vehicle.PCMExecute(info, policy.KernelBytes, cancellation).ConfigureAwait(false))
                throw new InvalidDataException("The pinned E54 RAM kernel upload was not acknowledged.");
            cancellation.ThrowIfCancellationRequested();

            result.Stage = AutoCalKernelProbeStage.KernelVersion;
            await guarded.SetTimeout(TimeoutScenario.ReadProperty).ConfigureAwait(false);
            result.KernelVersion = await vehicle.GetKernelVersion(cancellation, maxRetries: 1).ConfigureAwait(false);
            cancellation.ThrowIfCancellationRequested();
            if (!policy.IsKernelVerified || result.KernelVersion != AutoCalKernelProbePolicy.ExpectedKernelVersion)
                throw new InvalidDataException("The running RAM kernel did not return the exact pinned E54 version.");

            // Exit only follows a verified kernel. Failure at any earlier step
            // deliberately performs no reset/exit/cleanup protocol operations.
            result.Stage = AutoCalKernelProbeStage.ExitKernel;
            await guarded.SetTimeout(TimeoutScenario.Minimum).ConfigureAwait(false);
            await vehicle.ExitKernel().ConfigureAwait(false);
            await ReceiveUntil(guarded, () => policy.IsExitConfirmed, "kernel exit acknowledgement").ConfigureAwait(false);

            result.Stage = AutoCalKernelProbeStage.PostExitIdentity;
            // Conservative operational margin for ROM startup after the exit
            // ACK. This is not a measured or asserted protocol requirement.
            await Task.Delay(TimeSpan.FromSeconds(10), cancellation).ConfigureAwait(false);
            await FixedIdentity(guarded, protocol, () => policy.IsPostExitIdentityVerified).ConfigureAwait(false);
            cancellation.ThrowIfCancellationRequested();
            result.Stage = AutoCalKernelProbeStage.Complete;
            result.Success = true;
        }
        catch (OperationCanceledException error)
        {
            result.Cancelled = true;
            result.Error = error.ToString();
        }
        catch (Exception error)
        {
            // Channel preserves uncertain partial I/O in a typed transport
            // fault, which may wrap cancellation instead of throwing OCE.
            result.Cancelled = cancellation.IsCancellationRequested;
            result.Error = error.ToString();
        }
        finally
        {
            // This is only a logical I/O barrier. Root/native owner keeps all
            // pending operations and performs host cleanup; we never Dispose it.
            guarded.Halt();
            result.InitialIdentityVerified = policy.IsInitialIdentityVerified;
            result.KernelVersionVerified = policy.IsKernelVerified;
            result.ExitAcknowledged = policy.IsExitConfirmed;
            result.PostExitIdentityVerified = policy.IsPostExitIdentityVerified;
            result.RamExecuteSubmitted = guarded.RamExecuteSubmitted;
            result.RamCopyReplyObserved = policy.RamCopyAcknowledgement != null;
            result.VpwTransmissions = guarded.Transmissions;
            result.VpwReceivedFrames = guarded.ReceivedFrames;
            result.RetainedQueueClearRequests = guarded.ClearRequests;
            // After a failed preparation/upload, a fresh bench power cycle is a
            // user action required for a future attempt, never done automatically.
            result.BenchPowerCycleRequired = guarded.PreparationStarted && (copyOnly || !result.Success);
        }
        return result;
    }

    private async Task FixedIdentity(GuardedDevice device, Protocol protocol, Func<bool> verified)
    {
        await device.SetTimeout(TimeoutScenario.Minimum).ConfigureAwait(false);
        if (!await device.SendMessage(protocol.CreateOperatingSystemIdReadRequest()).ConfigureAwait(false))
            throw new IOException("Identity request was not submitted.");
        await ReceiveUntil(device, verified, "fixed E54 identity").ConfigureAwait(false);
    }

    private async Task ReceiveUntil(GuardedDevice device, Func<bool> verified, string description)
    {
        var timer = Stopwatch.StartNew();
        for (int frames = 0; frames < 32 && timer.ElapsedMilliseconds < 3000; frames++)
        {
            cancellation.ThrowIfCancellationRequested();
            await device.ReceiveMessage().ConfigureAwait(false);
            cancellation.ThrowIfCancellationRequested();
            if (timer.ElapsedMilliseconds >= 3000)
                throw new TimeoutException("Reply arrived outside the 3-second " + description + " window.");
            if (verified()) return;
        }
        throw new TimeoutException("No valid " + description + " within the bounded receive-only window.");
    }

    // All Vehicle and notifier I/O passes this owner. It neither opens nor
    // closes the adapter. Base queues contain only already policy-checked bytes.
    private sealed class GuardedDevice : Device
    {
        private readonly AutoCalDevice inner;
        private readonly AutoCalKernelProbePolicy policy;
        private readonly CancellationToken cancellation;
        private bool halted;
        public int Transmissions { get; private set; }
        public int ReceivedFrames { get; private set; }
        public int ClearRequests { get; private set; }
        public bool PreparationStarted { get; private set; }
        public bool RamExecuteSubmitted { get; private set; }

        public GuardedDevice(AutoCalDevice inner, ILogger logger, AutoCalKernelProbePolicy policy, CancellationToken token)
            : base(logger)
        {
            this.inner = inner; this.policy = policy; cancellation = token;
            MaxSendSize = inner.MaxKernelSendSize; MaxReceiveSize = inner.MaxReceiveSize;
            Supports4X = false; Enable4xReadWrite = false;
            currentTimeoutScenario = TimeoutScenario.ReadProperty;
        }
        private void Check()
        {
            if (halted) throw new InvalidOperationException("The bounded kernel session is halted.");
            cancellation.ThrowIfCancellationRequested();
        }
        public void Halt() => halted = true;
        public override string GetDeviceType() => "AutoCal V2 bounded E54 RAM-kernel probe";
        public override Task<bool> Initialize() => throw new NotSupportedException("Caller owns adapter setup.");
        public override Task<bool> CheckDeviceConnection() => throw new NotSupportedException("No adapter query inside the VPW session.");
        public override Task<bool> IsCommandBroadcasting(byte command) => throw new NotSupportedException("No recovery probing inside this session.");
        protected override Task<bool> SetVpwSpeedInternal(VpwSpeed speed) => throw new NotSupportedException("No speed transitions in this session.");
        protected override void Dispose(bool disposing) { if (disposing) Halt(); }
        public override async Task<TimeoutScenario> SetTimeout(TimeoutScenario scenario)
        {
            Check();
            if (scenario != TimeoutScenario.Minimum && scenario != TimeoutScenario.ReadProperty && scenario != TimeoutScenario.SendKernel)
                throw new NotSupportedException("Timeout scenario is outside the bounded RAM-kernel session.");
            TimeoutScenario previous = currentTimeoutScenario;
            await inner.SetTimeout(scenario).ConfigureAwait(false);
            currentTimeoutScenario = scenario;
            return previous;
        }
        public override async Task<bool> SendMessage(Message message)
        {
            Check();
            try
            {
                byte[] bytes = message.GetBytes();
                policy.BeforeTransmit(bytes);
                // Mark before submission: a failure can leave bytes in flight.
                if (bytes.Length >= 4 && bytes[3] != 0x3C) PreparationStarted = true;
                if (bytes.Length >= 5 && bytes[3] == 0x36 && bytes[4] == 0x80) RamExecuteSubmitted = true;
                Transmissions++;
                bool sent = await inner.SendMessage(message).ConfigureAwait(false);
                cancellation.ThrowIfCancellationRequested();
                if (!sent) throw new IOException("AutoCal did not submit the guarded VPW command.");
                return true;
            }
            catch { Halt(); throw; }
        }
        protected override async Task Receive()
        {
            Check();
            try
            {
                Message reply = await inner.ReceiveMessage().ConfigureAwait(false);
                cancellation.ThrowIfCancellationRequested();
                if (reply == null) return;
                ReceivedFrames++;
                policy.ObserveReceive(reply.GetBytes());
                Enqueue(reply);
            }
            catch { Halt(); throw; }
        }
        public override void ClearMessageBuffer()
        {
            Check(); ClearRequests++;
            // Generic Query/Unlock/Exit request clearing. Retain pending host
            // and adapter bytes: receiving them through this wrapper ensures
            // stale/correlated replies are inspected by the same state policy.
            Logger.AddDebugMessage("Bounded AutoCal probe retained pending bytes on queue-clear request.");
        }
    }
}

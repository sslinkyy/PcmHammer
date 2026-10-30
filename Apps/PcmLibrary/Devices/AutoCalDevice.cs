// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace PcmHacking
{
    public enum AutoCalSetupProfile
    {
        RecordedE54Read,
        RecordedOrdinaryIdentification
    }

    /// <summary>
    /// Experimental AutoCal V2 long-header backend. Setup replies establish host
    /// protocol acceptance only. This class is deliberately absent from the live
    /// adapter factory until bus setup, speed and programming are bench qualified.
    /// D2XX belongs in the Windows boundary; this device also runs on saved/fake I/O.
    /// </summary>
    public sealed class AutoCalDevice : Device
    {
        public const string DeviceType = "AutoCal V2 (experimental)";
        // Maximum observed host VPW extents, not claimed firmware limits.
        public const int ObservedMaximumTransmitBytes = 1772;
        public const int ObservedMaximumReceiveBytes = 4108;
        private const byte Selector = 7;
        private const uint VpwMetadata = 0x10;
        private readonly AutoCalChannel channel;
        private readonly CancellationToken cancellation;
        private readonly AutoCalSetupProfile setupProfile;
        private bool initialized;
        private bool stopped;
        private bool disposed;
        private int initializationAttempted;
        private int receiveTimeout = 3000;

        public AutoCalDevice(AutoCalChannel channel, ILogger logger, CancellationToken cancellationToken = default(CancellationToken),
            AutoCalSetupProfile setupProfile = AutoCalSetupProfile.RecordedE54Read)
            : base(logger)
        {
            this.channel = channel ?? throw new ArgumentNullException(nameof(channel));
            cancellation = cancellationToken;
            if (!Enum.IsDefined(typeof(AutoCalSetupProfile), setupProfile)) throw new ArgumentOutOfRangeException(nameof(setupProfile));
            this.setupProfile = setupProfile;
            MaxSendSize = ObservedMaximumTransmitBytes;
            MaxReceiveSize = ObservedMaximumReceiveBytes;
            Supports4X = false;
            Enable4xReadWrite = false;
            SupportsSingleDpidLogging = false;
            SupportsStreamLogging = false;
            currentTimeoutScenario = TimeoutScenario.ReadProperty;
        }

        public bool AdapterSetupAccepted => initialized && !stopped && !disposed && !channel.IsFaulted;
        public bool HardwareProgrammingQualified => false;
        public AutoCalChannel Channel => channel;
        public override string GetDeviceType() => DeviceType;

        public override async Task<bool> Initialize()
        {
            if (disposed || stopped || channel.IsFaulted) return false;
            if (initialized) return true;
            if (Interlocked.Exchange(ref initializationAttempted, 1) != 0)
                throw new InvalidOperationException("AutoCal initialization was already attempted; do not replay a partial setup sequence.");
            // No silent purge: queued bytes may be another owner's or an incomplete
            // earlier session. Require a clean boundary before the first exchange.
            if (channel.BufferedByteCount != 0 || channel.PendingByteCount != 0)
                throw new InvalidOperationException("AutoCal has pending bytes before initialization; preserve and inspect them before starting a new session.");
            if (!await CheckDeviceConnection().ConfigureAwait(false)) return false;
            // HAPI cold long-header compatibility query and separate initialization.
            await Setup(0x8604, new byte[] { 0 }).ConfigureAwait(false);
            await Setup(0x8800, new byte[] { 0, 0 }).ConfigureAwait(false);
            // Recorded E54 read setup. The values are preserved; no speed or filter
            // meaning is invented. The type-3-only 8800{01,00} path is not used.
            if (setupProfile == AutoCalSetupProfile.RecordedE54Read)
            {
                await Setup(0x8603, new byte[] { 1, 0, 0xF4, 1 }).ConfigureAwait(false);
                await Setup(0x8604, new byte[] { 1, 0, 0x10, 0, 0, 0 }).ConfigureAwait(false);
            }
            else
            {
                // Read-12 HTX record 59 precedes ordinary 3C 0A exchanges at
                // 74/75 and 82/83. Zero form is retained without assuming that
                // it means physical bus OFF or selects a particular speed.
                await Setup(0x8604, new byte[6]).ConfigureAwait(false);
            }
            initialized = true;
            Logger.AddUserMessage("AutoCal V2 host setup accepted. Physical VPW operation and programming remain unqualified.");
            return true;
        }

        public override async Task<bool> CheckDeviceConnection()
        {
            if (disposed || channel.IsFaulted) return false;
            AutoCalChannelReply reply = await channel.ExchangeAsync(0x8201, Selector, 0,
                Array.Empty<byte>(), 3000, cancellation).ConfigureAwait(false);
            return !reply.IsCommandError && reply.Payload != null
                && reply.Payload.SequenceEqual(new byte[] { 0x41, 0x43, 0x56, 0x32, 0 });
        }

        private async Task Setup(ushort command, byte[] payload)
        {
            AutoCalChannelReply reply = await channel.ExchangeAsync(command, Selector, 0,
                payload, 3000, cancellation).ConfigureAwait(false);
            if (reply.IsCommandError)
            {
                stopped = true;
                throw new InvalidOperationException("AutoCal setup command " + command.ToString("X4")
                    + " returned a command error: " + reply.ExceptionStatus?.ToString("X4"));
            }
            Logger.AddDebugMessage("AutoCal setup " + command.ToString("X4") + " RX: "
                + BitConverter.ToString(reply.Frame.RawBytes).Replace('-', ' '));
        }

        public override async Task<bool> SendMessage(Message message)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));
            RequireSession();
            byte[] bytes = message.GetBytes();
            if (bytes.Length < 3 || bytes.Length > MaxSendSize)
                throw new ArgumentException("VPW message is outside this backend's observed payload extent.", nameof(message));
            Logger.AddDebugMessage("TX: " + message);
            await channel.SendCommandAsync(0x8A00, Selector, VpwMetadata, bytes,
                Math.Max(3000, receiveTimeout), cancellation).ConfigureAwait(false);
            // Exact host-byte submission. ECU acceptance is a later ReceiveMessage.
            return true;
        }

        protected override async Task Receive()
        {
            RequireSession();
            try
            {
                AutoCalChannelReply reply = await channel.ReadAsync(0x8A00, receiveTimeout, cancellation).ConfigureAwait(false);
                if (reply.IsCommandError)
                {
                    stopped = true;
                    throw new InvalidOperationException("AutoCal VPW command error: " + reply.ExceptionStatus?.ToString("X4"));
                }
                ValidateVpwMetadata(reply);
                byte[] bytes = reply.Payload!;
                if (bytes.Length == 0) return;
                Enqueue(new Message(bytes));
            }
            catch (AutoCalReadTimeoutException) { /* No bytes and no I/O remain; caller sees no message. */ }
        }

        public override void ClearMessageBuffer()
        {
            RequireSession();
            foreach (AutoCalChannelReply reply in channel.DrainAvailableVpwAsync(3000, cancellation).GetAwaiter().GetResult())
            {
                Logger.AddDebugMessage("AutoCal drained RX: " + BitConverter.ToString(reply.Frame.RawBytes).Replace('-', ' '));
                if (reply.IsCommandError)
                {
                    stopped = true;
                    throw new InvalidOperationException("AutoCal command error was pending during queue drain.");
                }
                ValidateVpwMetadata(reply);
            }
        }

        public override Task<TimeoutScenario> SetTimeout(TimeoutScenario scenario)
        {
            TimeoutScenario previous = currentTimeoutScenario;
            switch (scenario)
            {
                case TimeoutScenario.Minimum: receiveTimeout = 250; break;
                case TimeoutScenario.ReadProperty: receiveTimeout = 3000; break;
                case TimeoutScenario.ReadCrc: receiveTimeout = 5000; break;
                case TimeoutScenario.SendKernel: receiveTimeout = 10000; break;
                case TimeoutScenario.ReadMemoryBlock: receiveTimeout = 10000; break;
                case TimeoutScenario.EraseMemoryBlock: receiveTimeout = 30000; break;
                case TimeoutScenario.WriteMemoryBlock: receiveTimeout = 10000; break;
                case TimeoutScenario.Maximum: receiveTimeout = 30000; break;
                default: throw new NotSupportedException("AutoCal timeout scenario has not been implemented: " + scenario);
            }
            currentTimeoutScenario = scenario;
            return Task.FromResult(previous);
        }

        public override async Task<bool> IsCommandBroadcasting(byte command)
        {
            RequireSession();
            // Bounded receive only. Never send a poll or reprogram the bus here.
            AutoCalChannelReply reply;
            try { reply = await channel.ReadAsync(0x8A00, receiveTimeout, cancellation).ConfigureAwait(false); }
            catch (AutoCalReadTimeoutException) { return false; }
            if (reply.IsCommandError) { stopped = true; throw new InvalidOperationException("AutoCal returned an error while receiving."); }
            ValidateVpwMetadata(reply);
            byte[] bytes = reply.Payload!;
            if (bytes.Length != 0) Enqueue(new Message(bytes));
            return bytes.Length >= 4 && bytes[3] == command;
        }

        protected override Task<bool> SetVpwSpeedInternal(VpwSpeed newSpeed)
        {
            Logger.AddUserMessage("AutoCal independent 1x/4x transition is not qualified; speed change refused.");
            return Task.FromResult(false);
        }

        /// <summary>Recorded adapter cleanup only; does not establish bus OFF or physical 1x.</summary>
        public async Task StopRecordedSessionAsync()
        {
            RequireSession();
            stopped = true; // Block vehicle sends before any cleanup exchange.
            await Setup(0x8604, new byte[6]).ConfigureAwait(false);
            await Setup(0x8B01, new byte[] { 0, 1, 0, 0 }).ConfigureAwait(false);
            await Setup(0x8B01, new byte[] { 1, 1, 0, 0 }).ConfigureAwait(false);
            stopped = true;
        }

        private void ValidateVpwMetadata(AutoCalChannelReply reply)
        {
            AutoCalVpwEnvelope projection = AutoCalVpwEnvelope.Project(reply.Frame,
                AutoCalVpwRequestContext.ExplicitVpwRequest8A00Context);
            uint? metadata = projection.ReceiveReturnedMetadata;
            if (projection.Kind != AutoCalVpwProjectionKind.ReceivePayload || (metadata != 0 && metadata != 0x10)
                || reply.Frame.PayloadLength > MaxReceiveSize)
            {
                stopped = true;
                Logger.AddDebugMessage("AutoCal rejected RX outside observed VPW profile: "
                    + BitConverter.ToString(reply.Frame.RawBytes).Replace('-', ' '));
                throw new InvalidOperationException("AutoCal RX metadata or extent is outside the observed VPW profile; no bus message was enqueued.");
            }
        }

        private void RequireSession()
        {
            if (!AdapterSetupAccepted) throw new InvalidOperationException("AutoCal session is unavailable or faulted.");
            cancellation.ThrowIfCancellationRequested();
        }

        protected override void Dispose(bool disposing)
        {
            // No automatic bus/setup/reset commands, especially after a failed write.
            // Only explicit disposal closes transport; native owner retains failed cleanup.
            if (disposing)
            {
                disposed = true; // I/O is closed to callers even if native cleanup is retained.
                if (!channel.IsTransportDisposed) channel.Dispose();
            }
        }
    }
}

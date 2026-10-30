// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace PcmHacking
{
    /// <summary>
    /// Application bytes, after driver-specific USB packet status removal.
    /// Methods must return promptly with a task, respect the supplied bounds,
    /// and retain buffer ownership only until that task completes. D2XX already
    /// removes FTDI packet status bytes; a channel must not remove them again.
    /// </summary>
    public interface IAutoCalByteTransport : IDisposable
    {
        Task<int> Read(byte[] buffer, int offset, int count, int timeoutMs, CancellationToken cancellationToken);
        Task<int> Write(byte[] buffer, int offset, int count, int timeoutMs, CancellationToken cancellationToken);
        int PendingByteCount { get; }
    }

    public enum AutoCalChannelFailure
    {
        DeadlineExceeded, Cancelled, NoProgress, TransportFailure, InvalidTransferCount,
        InvalidPrefix, UnsupportedLength, InvalidCrc, InvalidTrailer, ContextMismatch,
        MalformedError, BufferCapacity, SessionFaulted
    }

    public sealed class AutoCalReadTimeoutException : TimeoutException
    {
        internal AutoCalReadTimeoutException() : base("No AutoCal VPW bytes arrived before the read deadline; no partial frame or pending I/O remains.") { }
    }

    /// <summary>Retains completion evidence even when an I/O task finishes after its caller timed out.</summary>
    public sealed class AutoCalTransferObservation
    {
        private readonly object sync = new object();
        private bool completed;
        private int? returned;
        private byte[] bytes = Array.Empty<byte>();
        private Exception? error;
        internal AutoCalTransferObservation(string operation, int requested) { Operation = operation; RequestedByteCount = requested; }
        public string Operation { get; }
        public int RequestedByteCount { get; }
        public bool IsCompleted { get { lock (sync) return completed; } }
        public int? ReturnedByteCount { get { lock (sync) return returned; } }
        public byte[] Bytes { get { lock (sync) return (byte[])bytes.Clone(); } }
        public Exception? Error { get { lock (sync) return error; } }
        internal void Complete(Task<int> task, byte[] buffer, int offset)
        {
            lock (sync)
            {
                if (completed) return;
                if (task.Status == TaskStatus.RanToCompletion)
                {
                    returned = task.Result;
                    // Invalid reported counts retain the entire requested buffer,
                    // explicitly marked by ReturnedByteCount outside the bounds.
                    int extent = task.Result >= 0 && task.Result <= RequestedByteCount ? task.Result : RequestedByteCount;
                    bytes = new byte[extent];
                    Array.Copy(buffer, offset, bytes, 0, extent);
                }
                else error = task.Exception ?? (Exception)new OperationCanceledException("Transport task cancelled without a byte count.");
                completed = true;
            }
        }
    }

    public sealed class AutoCalChannelException : IOException
    {
        private readonly byte[] commandBytes;
        private readonly byte[] bufferedBytes;
        internal AutoCalChannelException(AutoCalChannelFailure failure, string operation, ushort command,
            int transferred, int requested, byte[] outbound, byte[] buffered, bool deliveryUncertain,
            string message, AutoCalTransferObservation? transfer, Exception? inner = null) : base(message, inner)
        {
            Failure = failure;
            Operation = operation;
            Command = command;
            TransferredByteCount = transferred;
            RequestedByteCount = requested;
            commandBytes = (byte[])outbound.Clone();
            bufferedBytes = (byte[])buffered.Clone();
            DeliveryUncertain = deliveryUncertain;
            Transfer = transfer;
        }
        public AutoCalChannelFailure Failure { get; }
        public string Operation { get; }
        public ushort Command { get; }
        public int TransferredByteCount { get; }
        public int RequestedByteCount { get; }
        public bool DeliveryUncertain { get; }
        public AutoCalTransferObservation? Transfer { get; }
        public byte[] CommandBytes => (byte[])commandBytes.Clone();
        public byte[] BufferedReceiveBytes => (byte[])bufferedBytes.Clone();
    }

    public sealed class AutoCalChannelReply
    {
        internal AutoCalChannelReply(AutoCalHostFrame frame, ushort requestedCommand, bool error, ushort? status)
        {
            Frame = frame;
            RequestedCommand = requestedCommand;
            IsCommandError = error;
            ExceptionStatus = status;
        }
        public AutoCalHostFrame Frame { get; }
        public ushort RequestedCommand { get; }
        public bool IsCommandError { get; }
        public ushort? ExceptionStatus { get; }
        public byte[]? Payload => IsCommandError ? null : Frame.Payload;
    }

    /// <summary>
    /// Serialized long-header channel; no bus setup or firmware speed policy.
    /// Completion of SendCommandAsync means exact transport byte accounting,
    /// not adapter acceptance or an ECU acknowledgement. ReadAsync never sends.
    /// A partial/ambiguous transfer or rejected frame faults this channel; raw
    /// bytes remain available and no automatic retransmission/purge occurs.
    /// </summary>
    public sealed class AutoCalChannel : IDisposable
    {
        public const int MaximumReceivePayload = 0xC000;
        public const int MaximumReceiveFrame = MaximumReceivePayload + 15;
        public const int DefaultReceiveBufferCapacity = MaximumReceiveFrame * 2;
        private readonly IAutoCalByteTransport transport;
        private readonly SemaphoreSlim gate = new SemaphoreSlim(1, 1);
        private readonly object stateLock = new object();
        private readonly byte[] receiveBuffer;
        private int receiveCount;
        private bool disposed;
        private bool transportDisposed;
        private bool disposalInProgress;
        private Task? pendingIo;
        private AutoCalChannelException? fault;
        private Exception? cleanupException;
        private AutoCalTransferObservation? lastTransfer;
        private List<AutoCalChannelReply> lastDrainReplies = new List<AutoCalChannelReply>();

        public AutoCalChannel(IAutoCalByteTransport transport, int receiveBufferCapacity = DefaultReceiveBufferCapacity)
        {
            this.transport = transport ?? throw new ArgumentNullException(nameof(transport));
            if (receiveBufferCapacity < MaximumReceiveFrame || receiveBufferCapacity > DefaultReceiveBufferCapacity)
                throw new ArgumentOutOfRangeException(nameof(receiveBufferCapacity), "Capacity must hold one or two maximum long-header frames.");
            receiveBuffer = new byte[receiveBufferCapacity];
        }
        public bool IsFaulted { get { lock (stateLock) return fault != null; } }
        public AutoCalChannelException? Fault { get { lock (stateLock) return fault; } }
        public Exception? CleanupException { get { lock (stateLock) return cleanupException; } }
        public bool IsTransportDisposed { get { lock (stateLock) return transportDisposed; } }
        public int BufferedByteCount => Volatile.Read(ref receiveCount);
        public int PendingByteCount
        {
            get
            {
                CheckAvailable();
                int pending = transport.PendingByteCount;
                if (pending < 0) throw new IOException("Transport reported a negative pending byte count.");
                return checked(BufferedByteCount + pending);
            }
        }
        public AutoCalTransferObservation? LastTransfer { get { lock (stateLock) return lastTransfer; } }
        public IReadOnlyList<AutoCalChannelReply> LastDrainReplies { get { lock (stateLock) return lastDrainReplies.ToArray(); } }

        public async Task SendCommandAsync(ushort command, byte selector, uint callerMetadata, byte[] payload,
            int timeoutMs, CancellationToken cancellationToken = default)
        {
            byte[] encoded = AutoCalHostFrame.EncodeLongHeader(command, selector, callerMetadata, payload);
            var deadline = new Deadline(timeoutMs);
            await EnterAsync(deadline, cancellationToken).ConfigureAwait(false);
            try { await WriteAsync(command, encoded, deadline, cancellationToken).ConfigureAwait(false); }
            finally { gate.Release(); }
        }

        public async Task<AutoCalChannelReply> ReadAsync(ushort requestedCommand, int timeoutMs,
            CancellationToken cancellationToken = default)
        {
            ValidateContext(requestedCommand);
            var deadline = new Deadline(timeoutMs);
            await EnterAsync(deadline, cancellationToken).ConfigureAwait(false);
            try { return await ReadReplyAsync(requestedCommand, deadline, cancellationToken, Array.Empty<byte>()).ConfigureAwait(false); }
            finally { gate.Release(); }
        }

        public async Task<AutoCalChannelReply> ExchangeAsync(ushort command, byte selector, uint callerMetadata,
            byte[] payload, int timeoutMs, CancellationToken cancellationToken = default)
        {
            ValidateContext(command);
            byte[] encoded = AutoCalHostFrame.EncodeLongHeader(command, selector, callerMetadata, payload);
            var deadline = new Deadline(timeoutMs);
            await EnterAsync(deadline, cancellationToken).ConfigureAwait(false);
            try
            {
                await WriteAsync(command, encoded, deadline, cancellationToken).ConfigureAwait(false);
                return await ReadReplyAsync(command, deadline, cancellationToken, encoded).ConfigureAwait(false);
            }
            finally { gate.Release(); }
        }

        public async Task<IReadOnlyList<AutoCalChannelReply>> DrainAvailableVpwAsync(int timeoutMs,
            CancellationToken cancellationToken = default)
        {
            var deadline = new Deadline(timeoutMs);
            await EnterAsync(deadline, cancellationToken).ConfigureAwait(false);
            try
            {
                var replies = new List<AutoCalChannelReply>();
                lock (stateLock) lastDrainReplies = replies;
                while (PendingByteCount > 0)
                {
                    AutoCalChannelReply reply;
                    try { reply = await ReadReplyAsync(0x8A00, deadline, cancellationToken, Array.Empty<byte>()).ConfigureAwait(false); }
                    catch (AutoCalReadTimeoutException)
                    {
                        throw Fail(AutoCalChannelFailure.DeadlineExceeded, "drain", 0x8A00, receiveCount, 0,
                            Array.Empty<byte>(), false, "Drain deadline expired with previously observed pending bytes; no purge performed.");
                    }
                    lock (stateLock) replies.Add(reply);
                    // A bounded byte capacity also bounds expanded empty frames.
                    if (replies.Count > receiveBuffer.Length / 15)
                        throw Fail(AutoCalChannelFailure.BufferCapacity, "drain", 0x8A00, 0, 0,
                            Array.Empty<byte>(), false, "Drain reply capacity reached; unread bytes retained.");
                }
                return replies.AsReadOnly();
            }
            finally { gate.Release(); }
        }

        private static void ValidateContext(ushort command)
        {
            if (command != 0x8201 && command != 0x8603 && command != 0x8604 && command != 0x8800
                && command != 0x8B01 && command != 0x8A00)
                throw new ArgumentOutOfRangeException(nameof(command), "An explicitly supported model, setup or VPW receive context is required.");
        }

        private async Task EnterAsync(Deadline deadline, CancellationToken cancellationToken)
        {
            CheckAvailable();
            if (!await gate.WaitAsync(deadline.Remaining, cancellationToken).ConfigureAwait(false))
                throw new TimeoutException("AutoCal session gate deadline expired before this operation performed I/O.");
            try { CheckAvailable(); }
            catch { gate.Release(); throw; }
        }

        private void CheckAvailable()
        {
            lock (stateLock)
            {
                if (disposed) throw new ObjectDisposedException(nameof(AutoCalChannel));
                if (fault != null) throw new InvalidOperationException("AutoCal channel is faulted; no further I/O is permitted.", fault);
            }
        }

        private byte[] BufferedBytes()
        {
            var result = new byte[receiveCount];
            Array.Copy(receiveBuffer, result, receiveCount);
            return result;
        }

        private AutoCalChannelException Fail(AutoCalChannelFailure code, string operation, ushort command,
            int transferred, int requested, byte[] outbound, bool uncertain, string message, Exception? inner = null)
        {
            var error = new AutoCalChannelException(code, operation, command, transferred, requested,
                outbound, BufferedBytes(), uncertain, message, lastTransfer, inner);
            lock (stateLock) { if (fault == null) fault = error; }
            return error;
        }

        private async Task WriteAsync(ushort command, byte[] encoded, Deadline deadline, CancellationToken token)
        {
            int completed = 0;
            while (completed < encoded.Length)
            {
                int offset = completed;
                int count = encoded.Length - completed;
                int written = await IoAsync(t => transport.Write(encoded, offset, count, t, token), deadline, token,
                    "write", command, completed, encoded.Length, encoded, encoded, offset, count).ConfigureAwait(false);
                if (written < 0 || written > count)
                    throw Fail(AutoCalChannelFailure.InvalidTransferCount, "write", command, completed, encoded.Length,
                        encoded, true, "Transport returned an invalid write count.");
                if (written == 0)
                    throw Fail(AutoCalChannelFailure.NoProgress, "write", command, completed, encoded.Length,
                        encoded, true, "Transport made no write progress; command delivery is uncertain.");
                completed += written;
            }
        }

        private async Task<AutoCalChannelReply> ReadReplyAsync(ushort command, Deadline deadline, CancellationToken token, byte[] outbound)
        {
            while (true)
            {
                CheckAvailable();
                if (token.IsCancellationRequested)
                    throw Fail(AutoCalChannelFailure.Cancelled, "read", command, 0, 0, outbound,
                        outbound.Length != 0, "Receive cancelled; buffered bytes retained.");
                if (deadline.Remaining == 0)
                {
                    if (command == 0x8A00 && outbound.Length == 0 && receiveCount == 0)
                        throw new AutoCalReadTimeoutException();
                    throw Fail(AutoCalChannelFailure.DeadlineExceeded, "read", command, 0, 0, outbound,
                        outbound.Length != 0, "Receive deadline expired; buffered bytes retained.");
                }
                if (receiveCount >= 2 && (receiveBuffer[0] != 1 || receiveBuffer[1] != 0x52))
                    throw Fail(AutoCalChannelFailure.InvalidPrefix, "read", command, receiveCount, 0, outbound,
                        outbound.Length != 0, "Invalid long-header RX prefix; no resynchronization attempted.");
                if (receiveCount >= 12)
                {
                    int payloadLength = receiveBuffer[10] | receiveBuffer[11] << 8;
                    if (payloadLength > MaximumReceivePayload)
                        throw Fail(AutoCalChannelFailure.UnsupportedLength, "read", command, receiveCount, payloadLength + 15,
                            outbound, outbound.Length != 0, "Declared receive payload exceeds the traced 0xC000 bound.");
                    int extent = payloadLength + 15;
                    if (receiveCount >= extent)
                    {
                        var raw = new byte[extent];
                        Array.Copy(receiveBuffer, raw, extent);
                        AutoCalHostFrame frame = AutoCalHostFrame.ParseLongHeader(AutoCalHostDirection.DeviceToHost, raw);
                        if (!frame.CrcMatches)
                            throw Fail(AutoCalChannelFailure.InvalidCrc, "read", command, extent, extent, outbound,
                                outbound.Length != 0, "Outer envelope CRC mismatch; rejected bytes retained.");
                        if (frame.RxTrailingByte != 0x19)
                            throw Fail(AutoCalChannelFailure.InvalidTrailer, "read", command, extent, extent, outbound,
                                outbound.Length != 0, "This selected long-header profile requires trailing 0x19.");
                        AutoCalChannelReply reply = Classify(frame, command, outbound);
                        Array.Copy(receiveBuffer, extent, receiveBuffer, 0, receiveCount - extent);
                        receiveCount -= extent;
                        return reply;
                    }
                }
                int free = receiveBuffer.Length - receiveCount;
                if (free == 0)
                    throw Fail(AutoCalChannelFailure.BufferCapacity, "read", command, receiveCount, receiveBuffer.Length,
                        outbound, outbound.Length != 0, "Receive capacity reached; no bytes discarded.");
                var chunk = new byte[Math.Min(free, 4096)];
                int count = await IoAsync(t => transport.Read(chunk, 0, chunk.Length, t, token), deadline, token,
                    "read", command, receiveCount, chunk.Length, outbound, chunk, 0, chunk.Length).ConfigureAwait(false);
                if (count < 0 || count > chunk.Length)
                    throw Fail(AutoCalChannelFailure.InvalidTransferCount, "read", command, receiveCount, chunk.Length,
                        outbound, outbound.Length != 0, "Transport returned an invalid read count.");
                if (count == 0)
                {
                    // A driver timeout can return zero before the end-to-end deadline.
                    await Task.Yield();
                    continue;
                }
                Array.Copy(chunk, 0, receiveBuffer, receiveCount, count);
                receiveCount += count;
            }
        }

        private AutoCalChannelReply Classify(AutoCalHostFrame frame, ushort command, byte[] outbound)
        {
            byte[] header = frame.OpaqueHeaderBytes;
            ushort marker = (ushort)(header[0] | header[1] << 8);
            if (marker == 0xFF00)
            {
                byte[] payload = frame.Payload;
                if (payload.Length < 4)
                    throw Fail(AutoCalChannelFailure.MalformedError, "read", command, frame.RawBytes.Length, frame.RawBytes.Length,
                        outbound, outbound.Length != 0, "Error envelope lacks command echo and status.");
                ushort echo = (ushort)(payload[0] | payload[1] << 8);
                if (echo != command)
                    throw Fail(AutoCalChannelFailure.ContextMismatch, "read", command, frame.RawBytes.Length, frame.RawBytes.Length,
                        outbound, outbound.Length != 0, "Error command echo differs from the requested context.");
                return new AutoCalChannelReply(frame, command, true, (ushort)(payload[2] | payload[3] << 8));
            }
            if (command != 0x8A00 && marker != command)
                throw Fail(AutoCalChannelFailure.ContextMismatch, "read", command, frame.RawBytes.Length, frame.RawBytes.Length,
                    outbound, outbound.Length != 0, "Normal command echo differs from the requested context.");
            return new AutoCalChannelReply(frame, command, false, null);
        }

        private async Task<int> IoAsync(Func<int, Task<int>> invoke, Deadline deadline, CancellationToken token,
            string operation, ushort command, int completed, int requested, byte[] outbound, byte[] ioBuffer, int ioOffset, int ioCount)
        {
            int remaining = deadline.Remaining;
            // The monotonic deadline can expire between the caller's idle check
            // and this pre-call boundary. No transport call exists in this case,
            // so it must have the same reusable empty-read semantics.
            if (!token.IsCancellationRequested && remaining == 0 && operation == "read"
                && command == 0x8A00 && outbound.Length == 0 && receiveCount == 0)
                throw new AutoCalReadTimeoutException();
            if (token.IsCancellationRequested || remaining == 0)
                throw Fail(token.IsCancellationRequested ? AutoCalChannelFailure.Cancelled : AutoCalChannelFailure.DeadlineExceeded,
                    operation, command, completed, requested, outbound, operation == "write" || outbound.Length != 0,
                    "Operation interrupted before the next transport call.");
            Task<int> io;
            var observation = new AutoCalTransferObservation(operation, ioCount);
            try
            {
                lock (stateLock)
                {
                    CheckAvailable();
                    io = invoke(remaining) ?? throw new InvalidOperationException("Transport returned no task.");
                    pendingIo = io;
                    lastTransfer = observation;
                }
            }
            catch (Exception error)
            {
                throw Fail(AutoCalChannelFailure.TransportFailure, operation, command, completed, requested, outbound,
                    operation == "write" || outbound.Length != 0, "Transport invocation failed; delivery may be ambiguous.", error);
            }
            _ = io.ContinueWith(t => observation.Complete(t, ioBuffer, ioOffset), CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            using (var timer = CancellationTokenSource.CreateLinkedTokenSource(token))
            {
                Task elapsed = Task.Delay(remaining, timer.Token);
                Task winner = await Task.WhenAny(io, elapsed).ConfigureAwait(false);
                if (!io.IsCompleted || token.IsCancellationRequested)
                {
                    // Keep the task and its private buffer owned until it completes.
                    _ = io.ContinueWith(t => { var observed = t.Exception; }, CancellationToken.None,
                        TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                    throw Fail(token.IsCancellationRequested ? AutoCalChannelFailure.Cancelled : AutoCalChannelFailure.DeadlineExceeded,
                        operation, command, completed, requested, outbound, operation == "write" || outbound.Length != 0,
                        "Transport deadline/cancellation interrupted an in-flight operation; session faulted.");
                }
                timer.Cancel();
                try
                {
                    int count = await io.ConfigureAwait(false);
                    observation.Complete(io, ioBuffer, ioOffset);
                    if (deadline.Remaining == 0 && !(operation == "read" && count == 0 && command == 0x8A00 && outbound.Length == 0 && receiveCount == 0))
                        throw Fail(AutoCalChannelFailure.DeadlineExceeded, operation, command, completed, requested, outbound,
                            operation == "write" || outbound.Length != 0, "I/O completed after the operation deadline; completion evidence retained.");
                    return count;
                }
                catch (AutoCalChannelException) { throw; }
                catch (Exception error)
                {
                    throw Fail(error is OperationCanceledException ? AutoCalChannelFailure.Cancelled : AutoCalChannelFailure.TransportFailure,
                        operation, command, completed, requested, outbound, operation == "write" || outbound.Length != 0,
                        "Transport task failed; session faulted.", error);
                }
                finally { lock (stateLock) { if (ReferenceEquals(pendingIo, io)) pendingIo = null; } }
            }
        }

        public void Dispose()
        {
            Task? active;
            lock (stateLock) { disposed = true; active = pendingIo; }
            if (active != null && !active.IsCompleted)
                _ = active.ContinueWith(_ => DisposeTransport(), CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            else DisposeTransport();
        }

        private void DisposeTransport()
        {
            lock (stateLock)
            {
                if (transportDisposed || disposalInProgress) return;
                disposalInProgress = true;
            }
            try
            {
                transport.Dispose();
                lock (stateLock) { transportDisposed = true; cleanupException = null; }
            }
            catch (Exception error) { lock (stateLock) cleanupException = error; }
            finally { lock (stateLock) disposalInProgress = false; }
        }

        private sealed class Deadline
        {
            private readonly Stopwatch watch = Stopwatch.StartNew();
            private readonly int timeout;
            public Deadline(int timeoutMs)
            {
                if (timeoutMs <= 0) throw new ArgumentOutOfRangeException(nameof(timeoutMs));
                timeout = timeoutMs;
            }
            public int Remaining => (int)Math.Max(0, timeout - watch.ElapsedMilliseconds);
        }
    }
}

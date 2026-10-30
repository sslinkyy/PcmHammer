// SPDX-License-Identifier: GPL-3.0-only
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using PcmHacking;
using Tests;

// Bounded profiles: USB-only setup, one E54 OS-ID request, or a pinned RAM-kernel
// execution/exit experiment, optionally reading the pinned baseline. Flash
// programming is absent. DeviceFactory and
// ordinary CLI selection remain unchanged. Plans load no native driver.
internal static class Program
{
    static readonly object JournalSync = new();
    static void WriteEvent(StreamWriter writer, object item)
    { lock (JournalSync) { writer.WriteLine(JsonSerializer.Serialize(item)); writer.Flush(); } }
    const string Dll = @"C:\Program Files (x86)\EFILive\Drivers\EFILive\Win-7-8-10\amd64\ftd2xx64.dll";
    const string DllHash = "91185415e0a1cd8ad09a5b644130554867ee4c4975c7aa71ee6da15d2645d9a2";
    const string Header = @"C:\Program Files (x86)\EFILive\Drivers\EFILive\Win-7-8-10\ftd2xx.h";
    const string HeaderHash = "cf2ad290c68137373b26629bf9feed6f4847f4e9e5cde4b980a212cebeb4ff6a";
    static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
    static object? NativeFailure(Exception? error)
    {
        if (error is AutoCalNativeTransferException native)
            return new { native.Sending, native.Status, native.Transferred, hex = Convert.ToHexString(native.Bytes) };
        return error?.InnerException == null ? null : NativeFailure(error.InnerException);
    }
    static string Root()
    {
        for (DirectoryInfo? item = new(AppContext.BaseDirectory); item != null; item = item.Parent)
            if (File.Exists(Path.Combine(item.FullName, "Tools", "AL5", "AutoCalBackendProbe", "AutoCalBackendProbe.csproj"))) return item.FullName;
        throw new InvalidOperationException("Run the in-checkout build so source provenance can be recorded.");
    }
    static object Plan(string root, ProbeProfile profile, AutoCalKernelProbePolicy? kernelPolicy, bool copyOnly, bool recordedReadSetup)
    {
        string[] sources = { "Apps/PcmLibrary/AutoCalHostFrame.cs", "Apps/PcmLibrary/AutoCalChannel.cs",
            "Apps/PcmLibrary/AutoCalVpwEnvelope.cs", "Apps/PcmLibrary/AutoCalSetupResponse.cs",
            "Apps/PcmLibrary/Devices/AutoCalDevice.cs", "Apps/PcmLibraryWindowsApi/Ports/AutoCalD2xxTransport.cs",
            "Tools/AL5/AutoCalBackendProbe/Program.cs", "Tools/AL5/AutoCalBackendProbe/ProbeProfile.cs",
            "Tools/AL5/AutoCalBackendProbe/KernelRequestGuard.cs", "Tools/AL5/AutoCalKernelProbePolicy.cs",
            "Tools/AL5/AutoCalKernelProbeSession.cs",
            "Tools/AL5/AutoCalBackendProbe/AutoCalBackendProbe.csproj",
            "Apps/PcmLibrary/CKernelReader.cs", "Apps/PcmLibrary/CKernelVerifier.cs", "Apps/PcmLibrary/Misc/Crc.cs",
            "Apps/PcmLibrary/Misc/Query.cs", "Apps/PcmLibrary/Misc/FlashChip.cs",
            "Apps/PcmLibrary/Misc/ToolPresentNotifier.cs", "Apps/PcmLibrary/Vehicle.Kernel.cs", "Apps/PcmLibrary/Vehicle.cs",
            "Apps/PcmLibrary/Messages/Protocol.ReadWrite.cs", "Apps/PcmLibrary/Messages/Protocol.Kernel.cs" };
        if (Hash(Dll) != DllHash || Hash(Header) != HeaderHash) throw new InvalidDataException("Native DLL/header pin changed.");
        bool fullRead = kernelPolicy?.FullReadEnabled == true;
        bool shortRead = kernelPolicy?.ShortReadEnabled == true;
        bool zeroSubmode = kernelPolicy?.UsesZeroSubmodeKernel == true;
        bool readEnabled = fullRead || shortRead;
        if (readEnabled && (new FileInfo(AutoCalKernelProbePolicy.DefaultBaselinePath).Length != AutoCalKernelProbePolicy.FullReadLength
            || Hash(AutoCalKernelProbePolicy.DefaultBaselinePath) != AutoCalKernelProbePolicy.ExpectedBaselineSha256))
            throw new InvalidDataException("Saved GT baseline does not match the pinned image.");
        int fullReadVpwLimit = AutoCalKernelProbePolicy.MaximumFullReadToolPresentAttempts + 11
            + AutoCalKernelProbePolicy.ReadBlockCount + 7 * AutoCalKernelProbePolicy.MaximumCrcQueriesPerRange;
        return new { schema = "autocal-backend-bounded-probe-plan-v4",
            profile = kernelPolicy == null ? profile.Name : (copyOnly ? "e54-ram-copy" : fullRead ? "e54-read-baseline"
                : recordedReadSetup ? "e54-read-prefix-recorded-setup" : zeroSubmode ? "e54-read-prefix-submode-zero"
                : shortRead ? "e54-read-prefix" : "e54-kernel-info"),
            source_sha256 = sources.ToDictionary(x => x, x => Hash(Path.Combine(root, x))),
            native_dll = Dll, native_sha256 = DllHash, header_sha256 = HeaderHash,
            probe_sha256 = Hash(Assembly.GetExecutingAssembly().Location), pcmlibrary_sha256 = Hash(typeof(AutoCalDevice).Assembly.Location),
            maximum_application_commands = kernelPolicy == null ? profile.Requests.Length : (copyOnly ? 42 : fullRead ? fullReadVpwLimit + 7 : shortRead ? 51 + (recordedReadSetup ? 3 : 0) : 49),
            maximum_vpw_payload_commands = kernelPolicy == null ? (profile.ReadsE54Identity ? 1 : 0) : (copyOnly ? 38 : fullRead ? fullReadVpwLimit : shortRead ? 44 : 42),
            overall_timeout_seconds = fullRead ? 900 : kernelPolicy != null ? 180 : 45,
            live_kernel_execution_enabled = kernelPolicy != null && !copyOnly,
            full_baseline_read_enabled = fullRead,
            baseline_prefix_read_enabled = shortRead,
            recorded_read_setup_experiment = recordedReadSetup,
            zero_submode_kernel_experiment = zeroSubmode,
            flash_programming_enabled = false,
            physical_bus_transmissions = "unmeasured", requires_obd_disconnected = !profile.ReadsE54Identity,
            requires_isolated_e54_bench = profile.ReadsE54Identity,
            expected_osid = profile.ReadsE54Identity ? (uint?)ProbeProfile.ExpectedOperatingSystem : null,
            commands = kernelPolicy == null ? profile.Requests.Select(Convert.ToHexString).ToArray()
                : copyOnly ? new[] { "Exact ordinary-profile model/setup", "Fixed initial OS-ID", "One suppression and bounded tool-present",
                    "One seed/key exchange using existing E54 algorithm", "One pinned RAM upload permission request",
                    "Pinned 279-byte RAM Copy of 267 bytes at FF97E0", "Receive acknowledgement; stop without execute or protocol cleanup; bench power cycle required" }
                : new[] { "Exact ordinary-profile model/setup", "Fixed initial OS-ID",
                    recordedReadSetup ? "Fixed 8603{0100F401} then 8604{010010000000} after identity, before preparation" : "Retain ordinary configuration",
                    "One suppression and bounded tool-present",
                    "One seed/key exchange using existing E54 algorithm", "One pinned RAM upload permission request",
                    zeroSubmode ? "Pinned 279-byte RAM Copy at FF97E0 with one derived reply-template byte (file 07AE: 01 to 00)"
                        : "Pinned 279-byte RAM Copy at FF97E0", "Pinned 1772-byte RAM Execute at FF9100",
                    "Exact kernel-version query/reply",
                    recordedReadSetup ? "Fixed 8604{000000000000} after kernel verification, before flash identity" : "No additional adapter configuration",
                    fullRead ? "Pinned flash ID, 128 sequential 4096-byte reads, pinned image SHA and seven controller CRC ranges"
                        : shortRead ? "Pinned flash ID, one 64-byte read at address zero and pinned baseline-prefix SHA; no CRC query" : "No flash read or CRC query",
                    "One kernel exit and final OS-ID", "Exact recorded adapter cleanup after confirmed exit" },
            baseline = !readEnabled ? null : new { path = AutoCalKernelProbePolicy.DefaultBaselinePath,
                sha256 = AutoCalKernelProbePolicy.ExpectedBaselineSha256, length = AutoCalKernelProbePolicy.FullReadLength,
                comparison_scope = fullRead ? "full-image" : "first-64-bytes",
                expected_read_length = fullRead ? AutoCalKernelProbePolicy.FullReadLength : AutoCalKernelProbePolicy.ShortReadLength,
                expected_read_sha256 = fullRead ? AutoCalKernelProbePolicy.ExpectedBaselineSha256 : AutoCalKernelProbePolicy.ExpectedShortReadSha256 },
            kernel = kernelPolicy == null ? null : new { path = AutoCalKernelProbePolicy.DefaultKernelPath,
                sha256 = AutoCalKernelProbePolicy.ExpectedKernelSha256, length = AutoCalKernelProbePolicy.ExpectedKernelLength,
                effective_sha256 = kernelPolicy.EffectiveKernelSha256,
                expected_read_reply_submode = kernelPolicy.ReadReplySubmode,
                derivation = !zeroSubmode ? null : new { scope = "owned-in-memory-clone-only", file_offset = 0x7AE,
                    ram_address = 0xFF98AE, source_byte = 1, effective_byte = 0,
                    source_file_modified = false, changed_byte_count = 1 },
                expected_version = AutoCalKernelProbePolicy.ExpectedKernelVersion,
                ram_messages_sha256 = kernelPolicy.UploadMessages.Select(x => Convert.ToHexString(SHA256.HashData(x))).ToArray() },
            limits = new[] { "Only the exact selected command sequence is admitted; no replay or alternate request.",
                "USB setup requires OBD unplugged. Identity mode admits only 6C10F03C0A, once. Kernel mode is confined to the isolated E54 and the pinned RAM asset.",
                "No flash erase/program, DTC-clear, arbitrary payload, alternative kernel, or speed-change operation is available.",
                fullRead ? "The baseline-read mode admits only the fixed flash ID, 128 ascending reads and seven CRC ranges. Data reads cannot replay; only the same pending CRC query may repeat, at most six times per range."
                    : shortRead ? "The prefix-read mode admits only the fixed flash ID and one 64-byte read at address zero. No data retry or CRC query is permitted; success does not verify the full image."
                        : "Flash identification, CRC and image reads are absent from this mode.",
                "Kernel-info is a fixed RAM-only experiment: exact observed Copy/Execute replies gate the known version, exit and final identity. Copy-only mode stops before execution and requires a bench power cycle.",
                "Recorded-setup prefix mode tests the observed configuration lifecycle; firmware meanings, persistence and receive effect remain unproven. Kernel, read address/length and VPW requests are unchanged.",
                "Zero-submode prefix mode changes one reply-template byte in the pinned RAM kernel clone. The raw reply checksum must validate with submode zero; ordinary configuration is retained. No extra acknowledgement is added.",
                "Replies do not establish physical VPW speed, programming or recovery. No speed change is requested.",
                "Partial/ambiguous transfers stop the session; cleanup only closes owned host resources after failure.", "Close failure retains owner; EOF does not release it." } };
    }

    sealed class Journal : IAutoCalByteTransport
    {
        readonly AutoCalD2xxTransport native;
        readonly StreamWriter writer;
        readonly Stopwatch watch = Stopwatch.StartNew();
        public RequestWriteGuard Guard { get; }
        public Journal(AutoCalD2xxTransport native, StreamWriter writer, RequestWriteGuard guard)
        { this.native = native; this.writer = writer; Guard = guard; }
        public int PendingByteCount => native.PendingByteCount;
        public void Event(string kind, object data)
        {
            WriteEvent(writer, new { elapsed_ms = watch.ElapsedMilliseconds, kind, data });
        }
        public async Task<int> Write(byte[] b, int at, int count, int timeout, CancellationToken token)
        {
            Guard.BeforeWrite(b, at, count);
            Event("write_attempt", new { offset = at, count, hex = Convert.ToHexString(b.AsSpan(at, count)) });
            int returned = await native.Write(b, at, count, timeout, token);
            Guard.CompleteWrite(returned);
            Event("write_completed", new { count = returned }); return returned;
        }
        public async Task<int> Read(byte[] b, int at, int count, int timeout, CancellationToken token)
        {
            int returned = await native.Read(b, at, count, timeout, token);
            Event("read_completed", new { count = returned, hex = Convert.ToHexString(b.AsSpan(at, returned)) }); return returned;
        }
        public void Dispose() { native.Dispose(); }
    }

    static async Task<int> Main(string[] args)
    {
        try
        {
            bool copyOnly = args.Length > 0 && (args[0] == "--e54-ram-copy" || args[0] == "--plan-e54-ram-copy");
            bool fullRead = args.Length > 0 && (args[0] == "--e54-read-baseline" || args[0] == "--plan-e54-read-baseline");
            bool recordedReadSetup = args.Length > 0 && (args[0] == "--e54-read-prefix-recorded-setup" || args[0] == "--plan-e54-read-prefix-recorded-setup");
            bool zeroSubmode = args.Length > 0 && (args[0] == "--e54-read-prefix-submode-zero" || args[0] == "--plan-e54-read-prefix-submode-zero");
            bool shortRead = recordedReadSetup || zeroSubmode || (args.Length > 0 && (args[0] == "--e54-read-prefix" || args[0] == "--plan-e54-read-prefix"));
            bool kernelInfo = copyOnly || fullRead || shortRead || (args.Length > 0 && (args[0] == "--e54-kernel-info" || args[0] == "--plan-e54-kernel-info"));
            bool identity = kernelInfo || (args.Length > 0 && (args[0] == "--e54-osid-read" || args[0] == "--plan-e54-osid-read"));
            ProbeProfile profile = new(identity);
            AutoCalKernelProbePolicy? kernelPolicy = kernelInfo
                ? new(File.ReadAllBytes(AutoCalKernelProbePolicy.DefaultKernelPath), fullRead, shortRead, zeroSubmode) : null;
            string operation = kernelInfo ? (copyOnly ? "e54-ram-copy" : fullRead ? "e54-read-baseline"
                : recordedReadSetup ? "e54-read-prefix-recorded-setup" : zeroSubmode ? "e54-read-prefix-submode-zero"
                : shortRead ? "e54-read-prefix" : "e54-kernel-info") : profile.Name;
            string root = Root(); object plan = Plan(root, profile, kernelPolicy, copyOnly, recordedReadSetup);
            if (args.Length == 0 || args.SequenceEqual(new[] { "--plan" }) || args.SequenceEqual(new[] { "--plan-e54-osid-read" })
                || args.SequenceEqual(new[] { "--plan-e54-kernel-info" }) || args.SequenceEqual(new[] { "--plan-e54-ram-copy" })
                || args.SequenceEqual(new[] { "--plan-e54-read-baseline" }) || args.SequenceEqual(new[] { "--plan-e54-read-prefix" })
                || args.SequenceEqual(new[] { "--plan-e54-read-prefix-recorded-setup" })
                || args.SequenceEqual(new[] { "--plan-e54-read-prefix-submode-zero" }))
            { Console.WriteLine(JsonSerializer.Serialize(plan, new JsonSerializerOptions { WriteIndented = true })); return 0; }
            if (args.Length != 6 || args[0] != "--" + operation
                || args[1] != (identity ? "--isolated-e54-bench" : "--obd-disconnected") || args[2] != "--serial" || args[4] != "--receipt")
                throw new ArgumentException("Use a listed --plan mode, or a listed live mode with its physical-state flag, --serial SERIAL and --receipt NEW.json.");
            // The separate copy-only and post-reset experiments established the
            // exact reply prerequisites (AUTOCAL_E54_RAM_COPY_20261030.json and
            // AUTOCAL_E54_POST_COPY_RESET_20261030.json). The fixed kernel-info
            // experiment established execution and normal exit. The separate
            // baseline-read mode may read/verify flash; neither can program it.
            string output = Path.GetFullPath(args[5]);
            string directory = Path.Combine(root, "LocalOnly", "AutoCalBackendProbe");
            if (!string.Equals(Path.GetDirectoryName(output), directory, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Receipt must be a new direct child of LocalOnly/AutoCalBackendProbe.");
            using FileStream receiptFile = new(output, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            using FileStream journalFile = new(output + ".journal.jsonl", FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            // Reserve all outputs before native access; never overwrite evidence.
            using FileStream? readbackFile = fullRead || shortRead ? new(output + ".readback.bin", FileMode.CreateNew, FileAccess.Write, FileShare.Read) : null;
            using StreamWriter journalWriter = new(journalFile) { AutoFlush = true };
            WriteEvent(journalWriter, new { kind = "plan", data = plan, serial = args[3] });
            using CancellationTokenSource cancel = new(TimeSpan.FromSeconds(fullRead ? 900 : kernelInfo ? 180 : 45));
            ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; cancel.Cancel(); };
            Console.CancelKeyPress += handler;
            AutoCalD2xxTransport? native = null; AutoCalChannel? channel = null; AutoCalDevice? device = null;
            Journal? transport = null;
            bool setupAccepted = false, cleanupAccepted = false;
            uint? operatingSystem = null;
            string? identityReply = null;
            int receivedVpwFrames = 0;
            AutoCalKernelProbeResult? kernelResult = null;
            string? failure = null;
            try
            {
                native = AutoCalD2xxTransport.OpenPinned(args[3], Dll, DllHash);
                RequestWriteGuard guard = kernelPolicy == null ? new ExactRequestGuard(profile) : new KernelRequestGuard(kernelPolicy, copyOnly, recordedReadSetup);
                transport = new(native, journalWriter, guard);
                transport.Event("opened", new { native.Serial, native.Description, pending = native.PendingByteCount });
                channel = new(transport);
                device = new(channel, new TestLogger(), cancel.Token, profile.Setup);
                setupAccepted = await device.Initialize();
                transport.Event("setup_result", new { accepted = setupAccepted });
                if (!setupAccepted) throw new IOException("AutoCal identity/setup did not match.");
                if (kernelPolicy != null)
                {
                    if (channel.BufferedByteCount != 0 || channel.PendingByteCount != 0)
                        throw new IOException("Unconsumed bytes precede the kernel experiment; no purge or transmit is allowed.");
                    var sessionLogger = new TestLogger();
                    var session = new AutoCalKernelProbeSession(device, sessionLogger, kernelPolicy, cancel.Token, copyOnly, fullRead, shortRead, recordedReadSetup);
                    kernelResult = await session.RunAsync();
                    transport.Event("kernel_result", kernelResult);
                    transport.Event("session_messages", new { user = sessionLogger.UserMessages.ToString(), debug = sessionLogger.DebugMessages.ToString() });
                    // Preserve completed observations even when a later phase
                    // fails; final controller state remains explicit below.
                    receivedVpwFrames = kernelPolicy.ReceiveCount;
                    if (kernelPolicy.IsInitialIdentityVerified)
                    {
                        operatingSystem = AutoCalKernelProbePolicy.ExpectedOperatingSystem;
                        identityReply = Convert.ToHexString(kernelPolicy.IsPostExitIdentityVerified
                            ? kernelPolicy.PostExitIdentityReply! : kernelPolicy.InitialIdentityReply!);
                    }
                    if (readbackFile != null && kernelResult.ReadbackBytes != null)
                    {
                        readbackFile.Write(kernelResult.ReadbackBytes);
                        readbackFile.Flush(true);
                        transport.Event("readback_saved", new { path = readbackFile.Name, length = readbackFile.Length,
                            kernelResult.ReadbackScope, kernelResult.ReadbackSha256, kernelResult.ReadbackCrcVerified, kernelResult.BaselineMatched });
                    }
                    if (!kernelResult.Success || (copyOnly ? !kernelResult.RamCopyReplyObserved : !kernelPolicy.IsPostExitIdentityVerified))
                        throw new IOException("RAM kernel experiment stopped: " + kernelResult.Error);
                    if (fullRead && (!kernelPolicy.IsImageVerified || !kernelResult.BaselineMatched))
                        throw new IOException("Full read did not match the pinned baseline and all controller CRCs.");
                    if (shortRead && (!kernelPolicy.IsShortReadVerified || !kernelResult.BaselineMatched))
                        throw new IOException("Prefix read did not match the pinned 64-byte baseline prefix.");
                    if (recordedReadSetup && (!device.RecordedReadPreparationAccepted || !device.RecordedOrdinaryConfigurationRestored))
                        throw new IOException("Recorded configuration experiment did not complete both checked phases.");
                }
                else if (identity)
                {
                    if (channel.BufferedByteCount != 0 || channel.PendingByteCount != 0)
                        throw new IOException("Unconsumed bytes precede the one identity request; no purge or transmit is allowed.");
                    await device.SetTimeout(TimeoutScenario.Minimum);
                    if (!await device.SendMessage(profile.CreateOsRequest())) throw new IOException("Fixed identity request was not submitted.");
                    var deadline = Stopwatch.StartNew();
                    while (deadline.ElapsedMilliseconds < 3000 && !operatingSystem.HasValue)
                    {
                        cancel.Token.ThrowIfCancellationRequested();
                        Message reply = await device.ReceiveMessage();
                        if (reply == null) continue;
                        byte[] bytes = reply.GetBytes(); receivedVpwFrames++;
                        transport.Event("vpw_receive", new { hex = Convert.ToHexString(bytes), elapsed_receive_ms = deadline.ElapsedMilliseconds });
                        if (deadline.ElapsedMilliseconds >= 3000)
                            throw new TimeoutException("Reply arrived outside the three-second identity window; bytes retained, request will not be repeated.");
                        operatingSystem = profile.ParseIdentity(bytes);
                        if (operatingSystem.HasValue) identityReply = Convert.ToHexString(bytes);
                    }
                    if (!operatingSystem.HasValue) throw new TimeoutException("No matching E54 OS-ID reply. The request will not be repeated.");
                    transport.Event("identity_result", new { osid = operatingSystem, hex = identityReply,
                        physical_speed = "unmeasured", firmware_execution_state = "not established by identity alone" });
                }
                if (!copyOnly)
                {
                    await device.StopRecordedSessionAsync(); cleanupAccepted = true;
                    transport.Event("recorded_cleanup_result", new { accepted = true, buffered = channel.BufferedByteCount, pending = channel.PendingByteCount });
                    if (channel.BufferedByteCount != 0 || channel.PendingByteCount != 0) throw new IOException("Unconsumed bytes remain after recorded cleanup.");
                }
                else transport.Event("copy_only_stop", new { no_further_protocol_commands = true, bench_power_cycle_required = true,
                    buffered = channel.BufferedByteCount, pending = channel.PendingByteCount });
            }
            catch (Exception error)
            {
                failure = error.ToString();
                WriteEvent(journalWriter, new { kind = "failure", failure,
                    native = NativeFailure(error), late_native = NativeFailure(channel?.LastTransfer?.Error),
                    buffered_hex = channel?.Fault == null ? null : Convert.ToHexString(channel.Fault.BufferedReceiveBytes),
                    command_hex = channel?.Fault == null ? null : Convert.ToHexString(channel.Fault.CommandBytes) });
            }
            finally
            {
                try { if (device != null) device.Dispose(); else if (channel != null) channel.Dispose(); else native?.Dispose(); }
                catch (Exception error) { failure = (failure ?? "") + "\nCleanup: " + error; }
                // Do not close a transport concurrently with a native call that
                // outlived the channel deadline. The channel retains its task.
                while (channel != null && !channel.IsTransportDisposed && channel.CleanupException == null)
                    await Task.Delay(100);
                while (AutoCalD2xxTransport.RetainedCleanupCount != 0 || (channel?.CleanupException != null && !channel.IsTransportDisposed))
                {
                    Console.Error.WriteLine("AutoCal cleanup remains owned. Type retry-close to retry; EOF keeps this process alive.");
                    string? command = Console.ReadLine();
                    if (command == null) { using ManualResetEventSlim retainedOwner = new(false); retainedOwner.Wait(); }
                    if (command == "retry-close")
                    {
                        try { channel?.Dispose(); AutoCalD2xxTransport.RetryRetainedCleanup(); }
                        catch (Exception error) { Console.Error.WriteLine(error.Message); }
                    }
                }
                Console.CancelKeyPress -= handler;
            }
            journalWriter.Flush(); journalFile.Flush(true);
            object result = new { schema = "autocal-backend-bounded-probe-result-v4", plan,
                serial = args[3], setup_accepted = setupAccepted, recorded_cleanup_accepted = cleanupAccepted,
                vpw_payload_commands_started = transport?.Guard.VpwPayloadCommandsStarted ?? 0,
                vpw_payload_commands_completed = transport?.Guard.VpwPayloadCommandsCompleted ?? 0,
                physical_bus_transmissions = "unmeasured", operating_system = operatingSystem, identity_reply = identityReply,
                identity_reply_scope = identityReply == null ? null : kernelPolicy == null ? "ordinary-query"
                    : kernelPolicy.IsPostExitIdentityVerified ? "post-exit" : "initial-query-only",
                received_vpw_frames = receivedVpwFrames, physical_speed = "unmeasured", hardware_programming_qualified = false,
                kernel_result = kernelResult,
                readback_path = readbackFile?.Name, readback_saved_bytes = readbackFile?.Length,
                kernel_policy = kernelPolicy == null ? null : new { kernelPolicy.CurrentPhase, kernelPolicy.Failure,
                    kernelPolicy.TransmitAttempts, kernelPolicy.ReceiveCount, kernelPolicy.UnrelatedReceiveCount,
                    kernelPolicy.RamCopyAttempts, kernelPolicy.RamExecuteAttempts,
                    kernelPolicy.FullReadEnabled, kernelPolicy.ReadBlockAttempts, kernelPolicy.ReadBlockReplies,
                    kernelPolicy.ShortReadEnabled, kernelPolicy.IsShortReadVerified,
                    kernelPolicy.UsesZeroSubmodeKernel, kernelPolicy.EffectiveKernelSha256, kernelPolicy.ReadReplySubmode,
                    kernelPolicy.CrcQueryAttempts, kernelPolicy.VerifiedCrcRanges, kernelPolicy.IsImageVerified,
                    kernelPolicy.BaselineShaMatched, kernelPolicy.ComputedImageSha256,
                    ram_copy_ack = kernelPolicy.RamCopyAcknowledgement == null ? null : Convert.ToHexString(kernelPolicy.RamCopyAcknowledgement),
                    ram_execute_ack = kernelPolicy.RamExecuteAcknowledgement == null ? null : Convert.ToHexString(kernelPolicy.RamExecuteAcknowledgement),
                    ack_final_byte_meaning = "opaque; actual execution requires exact known kernel-version response" },
                failure, channel_fault = channel?.Fault?.ToString(), cleanup_exception = channel?.CleanupException?.ToString(),
                late_transfer = channel?.LastTransfer == null ? null : new { channel.LastTransfer.Operation,
                    channel.LastTransfer.RequestedByteCount, channel.LastTransfer.ReturnedByteCount,
                    channel.LastTransfer.IsCompleted, hex = Convert.ToHexString(channel.LastTransfer.Bytes),
                    error = channel.LastTransfer.Error?.ToString(), native = NativeFailure(channel.LastTransfer.Error) },
                transport_disposed = channel?.IsTransportDisposed, retained_native_owners = AutoCalD2xxTransport.RetainedCleanupCount };
            JsonSerializer.Serialize(receiptFile, result, new JsonSerializerOptions { WriteIndented = true }); receiptFile.Flush(true);
            Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
            return failure == null && setupAccepted && (copyOnly ? kernelResult?.RamCopyReplyObserved == true : cleanupAccepted) ? 0 : 1;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}

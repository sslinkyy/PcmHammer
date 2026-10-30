// SPDX-License-Identifier: GPL-3.0-only
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using PcmHacking;
using Tests;

// Two exact profiles: USB-only setup, or one ordinary E54 OS-ID request on an
// isolated bench. No programming path exists in this tool. DeviceFactory and
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
    static object Plan(string root, ProbeProfile profile)
    {
        string[] sources = { "Apps/PcmLibrary/AutoCalHostFrame.cs", "Apps/PcmLibrary/AutoCalChannel.cs",
            "Apps/PcmLibrary/AutoCalVpwEnvelope.cs", "Apps/PcmLibrary/AutoCalSetupResponse.cs",
            "Apps/PcmLibrary/Devices/AutoCalDevice.cs", "Apps/PcmLibraryWindowsApi/Ports/AutoCalD2xxTransport.cs",
            "Tools/AL5/AutoCalBackendProbe/Program.cs", "Tools/AL5/AutoCalBackendProbe/ProbeProfile.cs",
            "Tools/AL5/AutoCalBackendProbe/AutoCalBackendProbe.csproj" };
        if (Hash(Dll) != DllHash || Hash(Header) != HeaderHash) throw new InvalidDataException("Native DLL/header pin changed.");
        return new { schema = "autocal-backend-fixed-probe-plan-v2", profile = profile.Name,
            source_sha256 = sources.ToDictionary(x => x, x => Hash(Path.Combine(root, x))),
            native_dll = Dll, native_sha256 = DllHash, header_sha256 = HeaderHash,
            probe_sha256 = Hash(Assembly.GetExecutingAssembly().Location), pcmlibrary_sha256 = Hash(typeof(AutoCalDevice).Assembly.Location),
            maximum_application_commands = profile.Requests.Length, maximum_vpw_payload_commands = profile.ReadsE54Identity ? 1 : 0,
            physical_bus_transmissions = "unmeasured", requires_obd_disconnected = !profile.ReadsE54Identity,
            requires_isolated_e54_bench = profile.ReadsE54Identity,
            expected_osid = profile.ReadsE54Identity ? (uint?)ProbeProfile.ExpectedOperatingSystem : null,
            commands = profile.Requests.Select(Convert.ToHexString).ToArray(),
            limits = new[] { "Only the exact selected command sequence is admitted; no replay or alternate request.",
                "USB setup requires OBD unplugged. Identity mode admits only 6C10F03C0A, once, on the isolated E54 bench.",
                "Replies do not establish physical VPW speed, programming or recovery. No speed change is requested.",
                "Partial/ambiguous transfers stop the session; cleanup only closes owned host resources after failure.", "Close failure retains owner; EOF does not release it." } };
    }

    sealed class Journal : IAutoCalByteTransport
    {
        readonly AutoCalD2xxTransport native;
        readonly StreamWriter writer;
        readonly Stopwatch watch = Stopwatch.StartNew();
        public ExactRequestGuard Guard { get; }
        public Journal(AutoCalD2xxTransport native, StreamWriter writer, ProbeProfile profile)
        { this.native = native; this.writer = writer; Guard = new(profile); }
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
            bool identity = args.Length > 0 && (args[0] == "--e54-osid-read" || args[0] == "--plan-e54-osid-read");
            ProbeProfile profile = new(identity);
            string root = Root(); object plan = Plan(root, profile);
            if (args.Length == 0 || args.SequenceEqual(new[] { "--plan" }) || args.SequenceEqual(new[] { "--plan-e54-osid-read" }))
            { Console.WriteLine(JsonSerializer.Serialize(plan, new JsonSerializerOptions { WriteIndented = true })); return 0; }
            if (args.Length != 6 || args[0] != "--" + profile.Name
                || args[1] != (identity ? "--isolated-e54-bench" : "--obd-disconnected") || args[2] != "--serial" || args[4] != "--receipt")
                throw new ArgumentException("Use --plan, --plan-e54-osid-read, --usb-setup --obd-disconnected --serial SERIAL --receipt NEW.json, or --e54-osid-read --isolated-e54-bench --serial SERIAL --receipt NEW.json.");
            string output = Path.GetFullPath(args[5]);
            string directory = Path.Combine(root, "LocalOnly", "AutoCalBackendProbe");
            if (!string.Equals(Path.GetDirectoryName(output), directory, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Receipt must be a new direct child of LocalOnly/AutoCalBackendProbe.");
            using FileStream receiptFile = new(output, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            using FileStream journalFile = new(output + ".journal.jsonl", FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            using StreamWriter journalWriter = new(journalFile) { AutoFlush = true };
            WriteEvent(journalWriter, new { kind = "plan", data = plan, serial = args[3] });
            using CancellationTokenSource cancel = new(TimeSpan.FromSeconds(45));
            ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; cancel.Cancel(); };
            Console.CancelKeyPress += handler;
            AutoCalD2xxTransport? native = null; AutoCalChannel? channel = null; AutoCalDevice? device = null;
            Journal? transport = null;
            bool setupAccepted = false, cleanupAccepted = false;
            uint? operatingSystem = null;
            string? identityReply = null;
            int receivedVpwFrames = 0;
            string? failure = null;
            try
            {
                native = AutoCalD2xxTransport.OpenPinned(args[3], Dll, DllHash);
                transport = new(native, journalWriter, profile);
                transport.Event("opened", new { native.Serial, native.Description, pending = native.PendingByteCount });
                channel = new(transport);
                device = new(channel, new TestLogger(), cancel.Token, profile.Setup);
                setupAccepted = await device.Initialize();
                transport.Event("setup_result", new { accepted = setupAccepted });
                if (!setupAccepted) throw new IOException("AutoCal identity/setup did not match.");
                if (identity)
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
                await device.StopRecordedSessionAsync(); cleanupAccepted = true;
                transport.Event("recorded_cleanup_result", new { accepted = true, buffered = channel.BufferedByteCount, pending = channel.PendingByteCount });
                if (channel.BufferedByteCount != 0 || channel.PendingByteCount != 0) throw new IOException("Unconsumed bytes remain after recorded cleanup.");
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
            object result = new { schema = "autocal-backend-fixed-probe-result-v2", plan,
                serial = args[3], setup_accepted = setupAccepted, recorded_cleanup_accepted = cleanupAccepted,
                vpw_payload_commands_started = transport?.Guard.VpwPayloadCommandsStarted ?? 0,
                vpw_payload_commands_completed = transport?.Guard.VpwPayloadCommandsCompleted ?? 0,
                physical_bus_transmissions = "unmeasured", operating_system = operatingSystem, identity_reply = identityReply,
                received_vpw_frames = receivedVpwFrames, physical_speed = "unmeasured", hardware_programming_qualified = false,
                failure, channel_fault = channel?.Fault?.ToString(), cleanup_exception = channel?.CleanupException?.ToString(),
                late_transfer = channel?.LastTransfer == null ? null : new { channel.LastTransfer.Operation,
                    channel.LastTransfer.RequestedByteCount, channel.LastTransfer.ReturnedByteCount,
                    channel.LastTransfer.IsCompleted, hex = Convert.ToHexString(channel.LastTransfer.Bytes),
                    error = channel.LastTransfer.Error?.ToString(), native = NativeFailure(channel.LastTransfer.Error) },
                transport_disposed = channel?.IsTransportDisposed, retained_native_owners = AutoCalD2xxTransport.RetainedCleanupCount };
            JsonSerializer.Serialize(receiptFile, result, new JsonSerializerOptions { WriteIndented = true }); receiptFile.Flush(true);
            Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
            return failure == null && setupAccepted && cleanupAccepted ? 0 : 1;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}

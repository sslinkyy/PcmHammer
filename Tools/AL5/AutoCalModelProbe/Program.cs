// SPDX-License-Identifier: GPL-3.0-only
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PcmHacking;

namespace AutoCalModelProbe;

internal sealed record Options(string Mode, string? Receipt);

internal sealed class EvidenceWriter : IDisposable
{
    private readonly FileStream receipt;
    private readonly FileStream journal;
    private long journalBytes;
    private int events;
    private bool sealedJournal;
    private const long MaximumJournalBytes = 1_048_576;
    internal string ReceiptPath { get; }
    internal string JournalPath { get; }

    internal EvidenceWriter(string path, object plan)
    {
        ReceiptPath = Path.GetFullPath(path);
        JournalPath = ReceiptPath + ".journal.jsonl";
        // Both files are claimed before any target library load; never truncate.
        receipt = new FileStream(ReceiptPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        try { journal = new FileStream(JournalPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read); }
        catch { receipt.Dispose(); throw; }
        try { Append(new ProbeEvent("preflight", plan)); }
        catch { try { journal.Dispose(); } finally { receipt.Dispose(); } throw; }
    }

    internal void Append(ProbeEvent item)
    {
        if (sealedJournal) throw new InvalidOperationException("Evidence journal is sealed.");
        byte[] line = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(item) + "\n");
        if (++events > 256 || line.LongLength > MaximumJournalBytes - journalBytes)
            throw new IOException("Bounded evidence journal capacity reached.");
        journal.Write(line);
        journal.Flush(flushToDisk: true);
        journalBytes += line.Length;
    }

    internal string SealJournal()
    {
        if (!sealedJournal)
        {
            journal.Flush(flushToDisk: true);
            journal.Dispose();
            sealedJournal = true;
        }
        return D2xxNative.HashFile(JournalPath);
    }

    internal void Finish(object result)
    {
        // This newly claimed receipt is written exactly once. An interrupted run
        // leaves its exclusive journal and an incomplete receipt, never success.
        if (receipt.Position != 0) throw new InvalidOperationException("Receipt already published.");
        JsonSerializer.Serialize(receipt, result, new JsonSerializerOptions { WriteIndented = true });
        receipt.Flush(flushToDisk: true);
    }

    public void Dispose() { try { journal.Dispose(); } finally { receipt.Dispose(); } }
}

internal static class Program
{
    internal static Options Parse(string[] args)
    {
        if (args.Length == 0) return new Options("plan", null);
        if (args.SequenceEqual(new[] { "--plan" })) return new Options("plan", null);
        if (args.SequenceEqual(new[] { "--self-test" })) return new Options("self-test", null);
        if (args.Length == 4 && args[0] == "--query-model" && args[1] == "--obd-disconnected"
            && args[2] == "--receipt" && !string.IsNullOrWhiteSpace(args[3]))
            return new Options("query-model", args[3]);
        throw new ArgumentException("Use --plan (default), --self-test, or --query-model --obd-disconnected --receipt <new-file.json>. No other commands or payloads are accepted.");
    }

    private static string RepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory != null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Tools", "AL5", "AutoCalModelProbe", "AutoCalModelProbe.csproj"))
                && File.Exists(Path.Combine(directory.FullName, "Apps", "PcmLibrary", "AutoCalHostFrame.cs")))
                return directory.FullName;
            directory = directory.Parent;
        }
        throw new DirectoryNotFoundException("Run the developer tool built in its source checkout; source provenance is required.");
    }

    internal static object BuildPlan()
    {
        string root = RepositoryRoot();
        string[] sources = ["Tools/AL5/AutoCalModelProbe/AutoCalModelProbe.csproj",
            "Tools/AL5/AutoCalModelProbe/Program.cs", "Tools/AL5/AutoCalModelProbe/ModelQuery.cs",
            "Tools/AL5/AutoCalModelProbe/D2xxNative.cs", "Tools/AL5/AutoCalModelProbe/SelfTests.cs",
            "Apps/PcmLibrary/AutoCalHostFrame.cs"];
        var hashes = sources.ToDictionary(path => path, path => D2xxNative.HashFile(Path.Combine(root, path)));
        Assembly decoder = typeof(AutoCalHostFrame).Assembly;
        return new
        {
            Schema = "autocal-csharp-fixed-model-plan-v1", OfflinePlan = true,
            RepositoryRoot = root, SourceSha256 = hashes,
            ProbeAssembly = new { Path = Assembly.GetExecutingAssembly().Location,
                Sha256 = D2xxNative.HashFile(Assembly.GetExecutingAssembly().Location) },
            PcmLibraryAssembly = new { Path = decoder.Location, Sha256 = D2xxNative.HashFile(decoder.Location),
                decoder.FullName },
            NativeFiles = D2xxNative.VerifyFiles(),
            FixedModel.Serial, IdentifierHex = FixedModel.Identifier.ToString("X8"), FixedModel.DeviceType,
            QueryHex = Convert.ToHexString(FixedModel.Query()), MaximumApplicationWrites = 1,
            FixedModel.ReplyBytes, FixedModel.MaxReads, FixedModel.ReadTimeoutMs, FixedModel.WriteTimeoutMs,
            MonotonicDeadlineSeconds = 20,
            Limits = new[] { "USB-only model query; OBD must be physically disconnected.",
                "Host model-query semantics and one direct trial do not establish vehicle transport or firmware side effects.",
                "No baud, flow-control, event-character, latency, USB-size, reset, purge or EEPROM calls.",
                "Native calls may outlive a timeout; no subsequent call except owned close is allowed after deadline/cancellation.",
                "A failed native close retains the process, module and file pin; only explicit retry-close repeats cleanup.",
                "No packet capture or USB transport losslessness claim; FT_Read returns D2XX data without USB FTDI status." }
        };
    }

    internal static void BestEffort(Action action)
    {
        try { action(); }
        catch (Exception) { /* Evidence failures must never abandon owned resources. */ }
    }

    // The object, native module and source-file pin remain strongly owned here
    // until device close and library release succeed. EOF is not authorization.
    internal static void RetainAndClean(IRetainedResources native, Action<ProbeEvent> journal,
        Func<string?>? readLine = null, Action? retainOnEof = null)
    {
        readLine ??= Console.ReadLine;
        retainOnEof ??= () => { using ManualResetEventSlim retained = new(false); retained.Wait(); };
        if (native.OwnsHandle && native.CloseAttempts == 0)
        {
            try
            {
                uint status = native.CloseOwnedHandle();
                BestEffort(() => journal(new ProbeEvent("exception_close_result", new { Status = status })));
            }
            catch (Exception error) { BestEffort(() => journal(new ProbeEvent("exception_close_error", error.ToString()))); }
        }
        string? releaseError = null;
        bool released = false;
        bool TryRelease()
        {
            if (native.OwnsHandle) return false;
            try { return native.TryReleaseLibrary(out releaseError); }
            catch (Exception error) { releaseError = error.ToString(); return false; }
        }
        released = TryRelease();
        while (!released)
        {
            BestEffort(() => journal(new ProbeEvent("cleanup_retained", new { native.OwnsHandle, native.OwnsLibraryOrPin, releaseError })));
            BestEffort(() => Console.Error.WriteLine("Cleanup remains unresolved. This process retains the device/library. Type retry-close to retry cleanup; EOF leaves the owner alive."));
            string? command;
            try { command = readLine(); }
            catch (Exception error)
            {
                BestEffort(() => journal(new ProbeEvent("cleanup_input_error", error.ToString())));
                Thread.Sleep(250);
                continue;
            }
            if (command == null)
            {
                // Ctrl+C requests cancellation but cannot discard an open native
                // handle. Keep this process alive when there is no input channel.
                retainOnEof();
                continue;
            }
            if (command != "retry-close") continue;
            if (native.OwnsHandle)
            {
                try
                {
                    uint status = native.CloseOwnedHandle();
                    BestEffort(() => journal(new ProbeEvent("manual_close_result", new { Status = status })));
                }
                catch (Exception error) { BestEffort(() => journal(new ProbeEvent("manual_close_error", error.ToString()))); }
            }
            released = TryRelease();
        }
    }

    private static int Query(Options options, object plan)
    {
        string root = RepositoryRoot();
        string outputDirectory = Path.GetFullPath(Path.Combine(root, "LocalOnly", "AutoCalModelProbe"));
        string path = Path.GetFullPath(options.Receipt!);
        if (!string.Equals(Path.GetDirectoryName(path), outputDirectory, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Receipt must be a new direct child of LocalOnly/AutoCalModelProbe.");
        // The build creates this directory. Do not create arbitrary directories.
        using EvidenceWriter writer = new(path, plan);
        using CancellationTokenSource cancellation = new();
        ConsoleCancelEventHandler cancel = (_, item) => { item.Cancel = true; cancellation.Cancel(); };
        Console.CancelKeyPress += cancel;
        ProbeBudget budget = new(ProbeBudget.MonotonicSeconds, cancellation.Token);
        D2xxNative native = new(budget);
        ModelResult? result = null;
        string? failure = null;
        DateTimeOffset started = DateTimeOffset.UtcNow;
        try
        {
            native.LoadVerified();
            result = ModelQuery.Run(native, budget, writer.Append);
        }
        catch (Exception error)
        {
            failure = error.ToString();
            BestEffort(() => writer.Append(new ProbeEvent("runner_error", failure)));
        }
        finally
        {
            // This cleanup cannot be skipped by receipt, console or session errors.
            RetainAndClean(native, writer.Append);
            Console.CancelKeyPress -= cancel;
        }
        bool success = failure == null && result?.Successful == true;
        string journalSha256 = writer.SealJournal();
        writer.Finish(new { Schema = "autocal-csharp-fixed-model-result-v1", StartedUtc = started,
            FinishedUtc = DateTimeOffset.UtcNow, Plan = plan, Result = result, Error = failure,
            Successful = success, CleanupProven = !native.OwnsHandle && !native.OwnsLibraryOrPin,
            Receipt = writer.ReceiptPath, Journal = writer.JournalPath,
            JournalSha256 = journalSha256 });
        Console.WriteLine(JsonSerializer.Serialize(new { Successful = success, CleanupProven = true, Receipt = path }));
        return success ? 0 : 1;
    }

    public static int Main(string[] args)
    {
        try
        {
            Options options = Parse(args);
            if (options.Mode == "self-test") return SelfTests.Run();
            object plan = BuildPlan(); // Only filesystem reads, even on the default path.
            if (options.Mode == "plan")
            {
                Console.WriteLine(JsonSerializer.Serialize(plan, new JsonSerializerOptions { WriteIndented = true }));
                return 0;
            }
            return Query(options, plan);
        }
        catch (Exception error)
        {
            Console.Error.WriteLine($"{error.GetType().Name}: {error.Message}");
            return 1;
        }
    }
}

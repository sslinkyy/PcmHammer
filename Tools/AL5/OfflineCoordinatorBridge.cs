// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PcmHacking;

// Test-only bounded stdio adapter. This project links no Vehicle, device or writer.
internal static class OfflineCoordinatorBridge
{
    private const int LineBudget = 256 * 1024; // Harness resource budget, not a vehicle protocol limit.

    private static string? ReadLine()
    {
        var text = new StringBuilder();
        while (true)
        {
            int next = Console.In.Read();
            if (next < 0) return text.Length == 0 ? null : throw new InvalidDataException("Incomplete JSON line.");
            if (next == '\n') return text.ToString();
            if (text.Length == LineBudget) throw new InvalidDataException("Bridge line resource budget exceeded.");
            text.Append((char)next);
        }
    }

    private static byte[] Bytes(JsonElement request, string field, int count)
    {
        string hex = request.GetProperty(field).GetString() ?? throw new ArgumentException("Missing hex field.");
        if (hex.Length != count*2) throw new ArgumentException("Wrong exact byte range for " + field);
        return Convert.FromHexString(hex);
    }

    private static int? Number(JsonElement request, string field)
    {
        var value = request.GetProperty(field);
        return value.ValueKind == JsonValueKind.Null ? null : value.GetInt32();
    }

    private static string Hash(byte[] value) => Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();

    private static void Pin(JsonElement request, string field, string actual)
    {
        if (request.GetProperty(field).GetString() != actual) throw new ArgumentException("Input digest mismatch: " + field);
    }

    private static void State(AL5OfflineProgrammingSession? session, string? attempt, object? detail = null, string? error = null)
    {
        var operation = session?.PendingOperation;
        Console.WriteLine(JsonSerializer.Serialize(new {
            attempt, state = session?.State.ToString(), observations = session?.Observations.Count,
            pending = operation == null ? null : new {
                sequence = operation.Sequence, phase = operation.Phase.ToString(),
                start = operation.StartAddress, length = operation.Length },
            detail, error, live_writes_enabled = false, automatic_retry_enabled = false,
            physical_recovery_verified = false }));
    }

    public static int Run()
    {
        string path = typeof(OfflineCoordinatorBridge).Assembly.Location;
        Console.WriteLine(JsonSerializer.Serialize(new { protocol = "al5-offline-coordinator-v1",
            bridge_sha256 = Hash(File.ReadAllBytes(path)), runtime = Environment.Version.ToString(),
            live_writes_enabled = false }));
        AL5OfflineProgrammingSession? session = null;
        string? attempt = null;
        string? line;
        while ((line = ReadLine()) != null)
        {
            try
            {
                using var document = JsonDocument.Parse(line);
                var request = document.RootElement;
                string action = request.GetProperty("action").GetString()!;
                string token = request.GetProperty("attempt").GetString()!;
                if (!Guid.TryParseExact(token, "N", out _)) throw new ArgumentException("Requires a 32-character attempt UUID.");
                if (action == "init")
                {
                    if (session != null) throw new InvalidOperationException("One attempt per bridge process.");
                    byte[] candidate = Bytes(request, "candidate", AL5CalibrationInspection.Length);
                    byte[] backup = Bytes(request, "backup", AL5ProgrammingWorkflow.CollateralLength);
                    Pin(request, "candidate_sha256", Hash(candidate));
                    Pin(request, "backup_sha256", Hash(backup));
                    session = new AL5OfflineProgrammingSession(candidate, backup);
                    attempt = token;
                    State(session, attempt);
                    continue;
                }
                if (session == null || token != attempt) throw new ArgumentException("Unknown bridge attempt.");
                var pending = session.PendingOperation;
                if (pending == null || request.GetProperty("sequence").GetInt32() != pending.Sequence)
                    throw new ArgumentException("Not the pending operation.");
                object? detail = null;
                switch (action)
                {
                    case "outcome":
                        var outcome = Enum.Parse<AL5OfflineOutcome>(request.GetProperty("outcome").GetString()!);
                        if (outcome == AL5OfflineOutcome.ModelCompleted && pending.Phase != AL5ProgrammingPhase.BootAndLoaderEntry)
                            throw new InvalidOperationException("Loader stages require native-model result facts.");
                        session.RecordModelOutcome(pending, outcome);
                        break;
                    case "loader":
                        byte[]? body = request.GetProperty("body").ValueKind == JsonValueKind.Null ? null : Bytes(request, "body", 3);
                        var sender = Enum.Parse<AL5ModeledSenderState>(request.GetProperty("sender").GetString()!);
                        var decision = session.RecordLoaderModelResult(pending, new AL5LoaderModelResult(body, sender,
                            Number(request, "stack_delta"), Number(request, "program_start"), Number(request, "program_bytes")));
                        detail = new { outcome = decision.Outcome.ToString(), reason = decision.Reason.ToString() };
                        break;
                    case "verify":
                    case "reconcile":
                        byte[] snapshot = Bytes(request, "snapshot", AL5ProgrammingWorkflow.SnapshotLength);
                        Pin(request, "snapshot_sha256", Hash(snapshot));
                        if (action == "verify")
                        {
                            var verified = session.RecordSavedVerification(pending, snapshot);
                            detail = new { exact_image = verified.ExactSavedImageMatch, snapshot_sha256 = verified.SnapshotSha256 };
                        }
                        else
                        {
                            var reconciled = session.AssessStoppedSnapshot(snapshot);
                            detail = new { disposition = reconciled.Disposition.ToString(),
                                exact_image = reconciled.ImageAssessment.ExactSavedImageMatch,
                                snapshot_sha256 = reconciled.ImageAssessment.SnapshotSha256,
                                stop_outcome = reconciled.StopObservation.Outcome.ToString(),
                                retry_enabled = reconciled.RetryEnabled, can_resume = reconciled.CanResumeStoppedSession,
                                matching_words = reconciled.PendingRangeComparison?.MatchingWords,
                                clear_words = reconciled.PendingRangeComparison?.AdditionalClearWords,
                                set_words = reconciled.PendingRangeComparison?.RequiresSetWords,
                                first_conflict = reconciled.PendingRangeComparison?.FirstRequiresSetAddress };
                        }
                        break;
                    default: throw new ArgumentException("Unknown bridge action.");
                }
                State(session, attempt, detail);
            }
            catch (Exception error) when (error is ArgumentException || error is InvalidOperationException ||
                error is JsonException || error is System.Collections.Generic.KeyNotFoundException ||
                error is FormatException || error is OverflowException)
            {
                State(session, attempt, error: error.Message);
            }
        }
        return 0;
    }
}

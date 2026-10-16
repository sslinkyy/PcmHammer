// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using PcmHacking;

internal static class LoaderModelReplyTest
{
    private static void Check(bool condition, string reason)
    { if (!condition) throw new Exception(reason); }

    private static AL5OfflineProgrammingSession At(Func<byte[]> fixture, AL5ProgrammingPhase phase)
    {
        var session = new AL5OfflineProgrammingSession(fixture(), new byte[AL5ProgrammingWorkflow.CollateralLength]);
        while (session.PendingOperation!.Phase != phase)
            session.RecordModelOutcome(session.PendingOperation, AL5OfflineOutcome.ModelCompleted);
        return session;
    }

    private static AL5LoaderModelDecision Observe(AL5OfflineProgrammingSession session, string? body,
        AL5ModeledSenderState sender, int? delta) => session.RecordLoaderModelResult(session.PendingOperation!,
            new AL5LoaderModelResult(body == null ? null : Convert.FromHexString(body), sender, delta));

    public static int Run(Func<byte[]> fixture)
    {
        int passed = 0;
        void Test(string name, Action action) { action(); passed++; Console.WriteLine("PASS AL5 loader reply: " + name); }
        Test("phase-specific replies advance exactly one modeled operation", () =>
        {
            foreach (var item in new[] {
                new { Phase = AL5ProgrammingPhase.ConditionalErase, Body = "7600ee" },
                new { Phase = AL5ProgrammingPhase.CalibrationBlocks, Body = "760073" },
                new { Phase = AL5ProgrammingPhase.CollateralRestoration, Body = "760073" },
                new { Phase = AL5ProgrammingPhase.Finalization, Body = "760086" } })
            {
                var session = At(fixture, item.Phase);
                int sequence = session.PendingOperation!.Sequence;
                var operation = session.PendingOperation!;
                var decision = session.RecordLoaderModelResult(operation, new AL5LoaderModelResult(
                    Convert.FromHexString(item.Body), AL5ModeledSenderState.Returned, 0, operation.StartAddress, operation.Length));
                Check(decision.Reason == AL5LoaderModelReplyReason.ExpectedReply && session.PendingOperation!.Sequence == sequence+1,
                    "Correct reply did not advance exactly once");
                Check(session.LoaderSessionReusable == null && !session.LiveWriteEnabled && !decision.Result.PhysicalDeliveryVerified,
                    "Model fact conferred physical delivery or session qualification");
            }
        });
        Test("negative, wrong-phase and malformed replies stop the attempt", () =>
        {
            foreach (string body in new[] { "760077", "760085", "760089", "7600f8", "7600ff", "760086", "760012", "7f0073" })
            {
                var session = At(fixture, AL5ProgrammingPhase.CalibrationBlocks);
                var operation = session.PendingOperation;
                var decision = Observe(session, body, AL5ModeledSenderState.Returned, 0);
                Check(session.State == AL5OfflineRunState.Stopped && session.PendingOperation == operation &&
                    decision.Outcome == AL5OfflineOutcome.ModelFailure && decision.Result.ResponseBodyHex == body,
                    "Invalid reply advanced or lost source body");
            }
        });
        Test("timeout wins over success-looking constructed status and reset stack", () =>
        {
            var session = At(fixture, AL5ProgrammingPhase.CalibrationBlocks);
            var decision = Observe(session, "760073", AL5ModeledSenderState.TimedOutWithSoftwareReentry, 0);
            Check(decision.Outcome == AL5OfflineOutcome.ReplyLost && decision.Reason == AL5LoaderModelReplyReason.SenderTimeout &&
                session.State == AL5OfflineRunState.Stopped, "Software reentry treated as successful delivery");
        });
        Test("unknown sender/body/stack and retained frames never advance", () =>
        {
            foreach (var item in new[] {
                new { Sender = AL5ModeledSenderState.Unobserved, Body = (string?)"760073", Delta = (int?)0, Reason = AL5LoaderModelReplyReason.SenderUnobserved },
                new { Sender = AL5ModeledSenderState.Returned, Body = (string?)null, Delta = (int?)0, Reason = AL5LoaderModelReplyReason.ReplyMissing },
                new { Sender = AL5ModeledSenderState.Returned, Body = (string?)"760073", Delta = (int?)null, Reason = AL5LoaderModelReplyReason.StackUnknown },
                new { Sender = AL5ModeledSenderState.Returned, Body = (string?)"760073", Delta = (int?)-4, Reason = AL5LoaderModelReplyReason.NonzeroStackDelta },
                new { Sender = AL5ModeledSenderState.Returned, Body = (string?)"760073", Delta = (int?)4, Reason = AL5LoaderModelReplyReason.NonzeroStackDelta } })
            {
                var session = At(fixture, AL5ProgrammingPhase.CalibrationBlocks);
                var decision = Observe(session, item.Body, item.Sender, item.Delta);
                Check(decision.Reason == item.Reason && session.State == AL5OfflineRunState.Stopped, "Unknown or pending state advanced");
                Check(ReferenceEquals(session.Observations.Last().LoaderDecision, decision), "Journal lost classification evidence");
            }
        });
        Test("replies cannot stand in for boot handoff or saved verification", () =>
        {
            foreach (var phase in new[] { AL5ProgrammingPhase.BootAndLoaderEntry, AL5ProgrammingPhase.IndependentVerification })
            {
                var session = At(fixture, phase);
                int count = session.Observations.Count;
                bool rejected = false;
                try { Observe(session, "760086", AL5ModeledSenderState.Returned, 0); }
                catch (InvalidOperationException) { rejected = true; }
                Check(rejected && count == session.Observations.Count, "Wrong reply contract changed journal");
            }
        });
        Test("a program ACK requires exact modeled block coverage", () =>
        {
            foreach (var coverage in new[] {
                new { Start = (int?)null, Count = (int?)null, Reason = AL5LoaderModelReplyReason.ProgramCoverageUnknown },
                new { Start = (int?)0x8000, Count = (int?)0, Reason = AL5LoaderModelReplyReason.ProgramCoverageMismatch },
                new { Start = (int?)0x8002, Count = (int?)256, Reason = AL5LoaderModelReplyReason.ProgramCoverageMismatch },
                new { Start = (int?)0x8000, Count = (int?)254, Reason = AL5LoaderModelReplyReason.ProgramCoverageMismatch } })
            {
                var session = At(fixture, AL5ProgrammingPhase.CalibrationBlocks);
                var decision = session.RecordLoaderModelResult(session.PendingOperation!, new AL5LoaderModelResult(
                    Convert.FromHexString("760073"), AL5ModeledSenderState.Returned, 0, coverage.Start, coverage.Count));
                Check(decision.Reason == coverage.Reason && session.State == AL5OfflineRunState.Stopped,
                    "Delay ACK or wrong block coverage accepted");
            }
        });
        Test("body ownership, malformed sizes and undefined sender values", () =>
        {
            byte[] bytes = Convert.FromHexString("760073");
            var result = new AL5LoaderModelResult(bytes, AL5ModeledSenderState.Returned, 0);
            bytes[2] = 0;
            Check(result.ResponseBodyHex == "760073", "Mutable source changed result");
            foreach (byte[] invalid in new[] { Array.Empty<byte>(), new byte[4] })
            {
                bool rejected = false;
                try { new AL5LoaderModelResult(invalid, AL5ModeledSenderState.Returned, 0); }
                catch (ArgumentException) { rejected = true; }
                Check(rejected, "Invalid body size accepted");
            }
            bool badSender = false;
            try { new AL5LoaderModelResult(null, (AL5ModeledSenderState)999, null); }
            catch (ArgumentOutOfRangeException) { badSender = true; }
            Check(badSender, "Unknown sender normalized");
        });
        return passed;
    }

    private static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static JsonDocument Evidence(string root, string document, string generator, string expectedHash)
    {
        string path = Path.Combine(root, "Docs", "AL5", document+".json");
        using var stream = File.OpenRead(path);
        Check(stream.Length <= 1048576, "Evidence report exceeds test harness resource budget");
        Check(Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant() == expectedHash,
            "Native evidence golden changed; review before updating its pin");
        stream.Position = 0;
        var json = JsonDocument.Parse(stream);
        try
        {
            var data = json.RootElement;
            Check(data.GetProperty("generator_sha256").GetString() == HashFile(Path.Combine(root, "Tools", "AL5", generator)), "Stale native generator");
            foreach (var dependency in data.GetProperty("dependency_sha256").EnumerateObject())
            {
                Check(Path.GetFileName(dependency.Name) == dependency.Name, "Unexpected dependency path");
                Check(dependency.Value.GetString() == HashFile(Path.Combine(root, "Tools", "AL5", dependency.Name)), "Stale native dependency");
            }
            string hash = data.TryGetProperty("payload_sha256", out var payload) ? payload.GetString()! : data.GetProperty("loader_sha256").GetString()!;
            Check(hash == "b545d9b2d078662466ab32d9cdeb5b3c38c840135e8aeca09f33760ec66780fa", "Wrong captured loader identity");
            return json;
        }
        catch { json.Dispose(); throw; }
    }

    public static int RunEvidence(Func<byte[]> fixture, string root)
    {
        int checkedSteps = 0;
        foreach (var source in new[] {
            new { Document = "LOADER_ERASE_FAILURE_EMULATION", Generator = "emulate_loader_erase_failures.py", SenderFacts = false, Hash = "8d169a1b0620307d3c223f65eb3e60d1475c6d1195cf83066cfc0bb794615383" },
            new { Document = "LOADER_ENTRY_EMULATION", Generator = "emulate_loader_entry.py", SenderFacts = false, Hash = "99c7a359416ad01ada3a01128f3ab209deac37220ae10f20d8be6c8d2142694a" },
            new { Document = "LOADER_ERROR_SENDER_EMULATION", Generator = "emulate_loader_error_sender.py", SenderFacts = true, Hash = "9656b612aba57e54e585a7387e424fdba12ebf62cf0298c7c1d2026df208bc87" } })
        {
            using var json = Evidence(root, source.Document, source.Generator, source.Hash);
            foreach (var scenario in json.RootElement.GetProperty("cases").EnumerateArray())
            {
                int replyIndex = 0;
                foreach (var step in scenario.GetProperty("steps").EnumerateArray())
                {
                    var replies = step.GetProperty("responses").EnumerateArray().ToArray();
                    if (replies.Length == 0) continue;
                    Check(replies.Length == 1, "Fixture has more than one constructed reply");
                    string body = replies[0].GetString()!;
                    // Select hypothetical host context from the producer's scenario, never its response code.
                    // The delay-only entry fixture is intentionally evaluated as an insufficient block ACK.
                    string name = scenario.GetProperty("name").GetString()!;
                    var phase = AL5ProgrammingPhase.CalibrationBlocks;
                    if (source.Document == "LOADER_ERASE_FAILURE_EMULATION")
                    {
                        bool programStep = name == "mixed_failures_and_success_do_not_unwind" && (replyIndex == 1 || replyIndex == 3) ||
                            name == "repeated_erase_then_id_failure" && replyIndex == 3;
                        phase = programStep ? AL5ProgrammingPhase.CalibrationBlocks : AL5ProgrammingPhase.ConditionalErase;
                    }
                    else if (source.SenderFacts && name.StartsWith("erase_", StringComparison.Ordinal))
                        phase = AL5ProgrammingPhase.ConditionalErase;
                    var sender = !source.SenderFacts ? AL5ModeledSenderState.Unobserved :
                        step.GetProperty("sender_timeout_jumps").GetArrayLength() != 0 ? AL5ModeledSenderState.TimedOutWithSoftwareReentry :
                        step.GetProperty("native_sender_returns").GetInt32() == 1 ? AL5ModeledSenderState.Returned : AL5ModeledSenderState.Unobserved;
                    var session = At(fixture, phase);
                    int ordinal = session.PendingOperation!.Sequence;
                    var decision = Observe(session, body, sender, step.GetProperty("stack_delta").GetInt32());
                    // These sources either omit native sender return facts or report failure/timeout.
                    Check(decision.Outcome != AL5OfflineOutcome.ModelCompleted && session.State == AL5OfflineRunState.Stopped &&
                        session.PendingOperation!.Sequence == ordinal, "Native evidence incorrectly allowed continuation");
                    checkedSteps++;
                    replyIndex++;
                }
            }
        }
        Check(checkedSteps == 27, "Native fixture coverage changed; review the examined cases");
        Console.WriteLine("PASS " + checkedSteps + " pinned native-model constructed replies; missing sender evidence stays unknown.");
        return 1;
    }
}

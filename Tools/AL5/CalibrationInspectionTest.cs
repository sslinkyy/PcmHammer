// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.IO;
using PcmHacking;

// This project compiles the production inspector/workflow with the BCL only. It cannot
// access Vehicle, adapter classes, or the PCM writer. Optional corpus files are
// read only and require explicit expected hashes and independently known fields.
internal static class CalibrationInspectionTest
{
    private static int passed;

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }

    private static void Test(string name, Action action)
    {
        action();
        passed++;
        Console.WriteLine("PASS " + name);
    }

    private static byte[] Fixture()
    {
        var image = new byte[AL5CalibrationInspection.Length];
        Put(image, 0x08024, "00E7B058");
        Put(image, 0x0A996, "11F70C68073E05A0040002D9");
        Put(image, 0x158A8, "00110009");
        // Golden values from the independently existing Python checksum.py,
        // not a second C# checksum implementation that could mirror a bug.
        Put(image, AL5CalibrationInspection.ChecksumAddress, "507CCC15");
        return image;
    }

    private static void Put(byte[] image, int address, string hex)
    {
        byte[] values = Convert.FromHexString(hex);
        Array.Copy(values, 0, image, address - AL5CalibrationInspection.StartAddress, values.Length);
    }

    private static void Blocked(AL5CalibrationFileReport report)
    {
        Check(!report.ReadyToFlash && !report.LiveWriteEnabled && !report.EditsAuthorizedForWriting && !report.LiveIdentityVerified,
            "File facts elevated into programming authorization or live identity");
    }

    private static void Blocked(AL5CalibrationComparisonReport report)
    {
        Check(!report.ReadyToFlash && !report.LiveWriteEnabled && !report.EditsAuthorizedForWriting && !report.LiveIdentityVerified,
            "Comparison elevated into programming authorization or live identity");
        Blocked(report.Baseline);
        Blocked(report.Candidate);
    }

    public static int Main(string[] args)
    {
        try
        {
            Test("Python golden checksum fixture and unchanged comparison", () =>
            {
                var report = AL5CalibrationInspection.Compare(Fixture(), Fixture());
                Check(report.FileChecksPass, "Known fixture rejected");
                Check(report.Baseline.ComputedChecksumHex == "507CCC15", "Python field disagrees");
                Check(report.Baseline.NativeChecksumValid == true && report.Baseline.BigEndianWordSum == 0, "Golden checksum/sum failed");
                Check(report.DifferencesComputed && report.DiffRanges.Count == 0 && report.ChangedByteCount == 0, "Unchanged files have differences");
                Blocked(report);
            });
            Test("Custom edit inspected without allowlist authorization", () =>
            {
                byte[] candidate = Fixture();
                candidate[0x821C - AL5CalibrationInspection.StartAddress] = 1;
                Put(candidate, AL5CalibrationInspection.ChecksumAddress, "74EDA6A4");
                var report = AL5CalibrationInspection.Compare(Fixture(), candidate);
                Check(report.FileChecksPass && report.Candidate.ComputedChecksumHex == "74EDA6A4", "Custom checksum crosscheck failed");
                Check(report.DiffRanges.Count == 2 && report.DiffRanges[0].StartAddress == 0x821C && report.DiffRanges[0].Length == 1,
                    "Custom edit diff incorrect");
                Check(report.DiffRanges[1].StartAddress == AL5CalibrationInspection.ChecksumAddress && report.DiffRanges[1].Length == 4,
                    "Checksum diff incorrect");
                Blocked(report);
            });
            Test("Zero word sum cannot substitute for native checksum", () =>
            {
                byte[] image = Fixture();
                image[image.Length - 4] ^= 1;
                uint sum = 0;
                for (int index = 0; index < image.Length - 2; index += 2)
                    sum += (uint)((image[index] << 8) | image[index + 1]);
                ushort compensation = unchecked((ushort)-sum);
                image[image.Length - 2] = (byte)(compensation >> 8);
                image[image.Length - 1] = (byte)compensation;
                var report = AL5CalibrationInspection.Inspect(image);
                Check(report.BigEndianWordSum == 0 && report.NativeChecksumValid == false && !report.ChecksPass,
                    "Zero-sum checksum collision accepted");
                Blocked(report);
            });
            Test("Checksum-valid anchor mismatch remains unsupported", () =>
            {
                byte[] image = Fixture();
                image[0x24] ^= 1;
                Put(image, AL5CalibrationInspection.ChecksumAddress, "B2486949");
                var report = AL5CalibrationInspection.Inspect(image);
                Check(report.NativeChecksumValid == true && report.BigEndianWordSum == 0, "Anchor-only golden field mismatch");
                Check(!report.KnownFamilyAnchorsMatch && !report.ChecksPass && report.InputErrors.Count == 1, "Wrong family accepted");
                Check(report.InputErrors[0].Contains("0x08024"), "Anchor address missing");
                Blocked(report);
            });
            Test("Malformed sizes produce structured unknown checks", () =>
            {
                foreach (int length in new[] { 0, 1, 57303, 57305, 131072, 1048576 })
                {
                    var report = AL5CalibrationInspection.Compare(Fixture(), new byte[length]);
                    Check(!report.Candidate.HasExactLength && !report.FileChecksPass && report.Candidate.ActualLength == length, "Bad size accepted");
                    Check(report.Candidate.Sha256 == null && report.Candidate.NativeChecksumValid == null && report.Candidate.BigEndianWordSum == null,
                        "Unsupported image contents scanned or reported as known");
                    Check(report.Candidate.InputErrors.Count == 1 && !report.DifferencesComputed && report.DiffRanges.Count == 0 && report.ChangedByteCount == 0,
                        "Malformed input yielded diff or missing error");
                    Check(report.Baseline.ChecksPass, "Other valid file lost its facts");
                    Blocked(report);
                }
            });
            Test("First and last byte ranges use absolute inclusive addresses", () =>
            {
                byte[] candidate = Fixture();
                candidate[0] ^= 1;
                candidate[candidate.Length - 1] ^= 1;
                var report = AL5CalibrationInspection.Compare(Fixture(), candidate);
                Check(report.ChangedByteCount == 2 && report.DiffRanges.Count == 2, "Boundary diff count incorrect");
                Check(report.DiffRanges[0].StartAddress == 0x8000 && report.DiffRanges[0].EndAddressInclusive == 0x8000,
                    "First byte address incorrect");
                Check(report.DiffRanges[1].StartAddress == 0x15FD7 && report.DiffRanges[1].EndAddressInclusive == 0x15FD7,
                    "Last byte address incorrect");
                Blocked(report);
            });
            Test("Reports are snapshots and collections reject mutation", () =>
            {
                byte[] baseline = Fixture();
                byte[] candidate = Fixture();
                byte[] before = (byte[])candidate.Clone();
                var report = AL5CalibrationInspection.Compare(baseline, candidate);
                Check(Convert.ToHexString(candidate) == Convert.ToHexString(before), "Inspector modified caller bytes");
                string? hash = report.Candidate.Sha256;
                candidate[0] ^= 1;
                baseline[0] ^= 1;
                Check(report.Candidate.Sha256 == hash && report.FileChecksPass && report.DiffRanges.Count == 0,
                    "Report retained mutable input");
                bool blocked = false;
                try { ((IList<AL5CalibrationDiffRange>)report.DiffRanges).Clear(); }
                catch (NotSupportedException) { blocked = true; }
                Check(blocked, "Diff collection mutable");
                blocked = false;
                try { ((IList<string>)report.Candidate.InputErrors).Add("injected"); }
                catch (NotSupportedException) { blocked = true; }
                Check(blocked, "Error collection mutable");
            });
            Test("All unequal bytes form one bounded range", () =>
            {
                byte[] before = new byte[AL5CalibrationInspection.Length];
                byte[] after = new byte[AL5CalibrationInspection.Length];
                Array.Fill(after, (byte)0xFF);
                var report = AL5CalibrationInspection.Compare(before, after);
                Check(report.DiffRanges.Count == 1 && report.DiffRanges[0].StartAddress == 0x8000 &&
                    report.DiffRanges[0].EndAddressInclusive == 0x15FD7 && report.ChangedByteCount == AL5CalibrationInspection.Length,
                    "Full-range boundary incorrect");
                Blocked(report);
            });
            Test("Null arguments fail explicitly", () =>
            {
                int rejected = 0;
                try { AL5CalibrationInspection.Inspect(null!); } catch (ArgumentNullException) { rejected++; }
                try { AL5CalibrationInspection.Compare(null!, Fixture()); } catch (ArgumentNullException) { rejected++; }
                try { AL5CalibrationInspection.Compare(Fixture(), null!); } catch (ArgumentNullException) { rejected++; }
                Check(rejected == 3, "Null boundary not explicit");
            });

            if (args.Length % 4 != 0) throw new ArgumentException("Use repeated --corpus or --reconstructed-corpus PATH EXPECTED_SHA256 EXPECTED_FIELD arguments.");
            int corpus = 0;
            passed += ProgrammingWorkflowTest.Run(Fixture);
            int reconstructed = 0;
            for (int index = 0; index < args.Length; index += 4)
            {
                bool fromExportDiff = args[index] == "--reconstructed-corpus";
                if (args[index] != "--corpus" && !fromExportDiff) throw new ArgumentException("Unknown argument: " + args[index]);
                string path = args[index + 1];
                string expectedHash = args[index + 2];
                string expectedField = args[index + 3];
                Test((fromExportDiff ? "Native-export diff reconstruction " : "Pinned native corpus ") + Path.GetFileName(path), () =>
                {
                    var report = AL5CalibrationInspection.Inspect(File.ReadAllBytes(path));
                    Check(report.Sha256 == expectedHash.ToLowerInvariant(), "Native corpus hash does not match selected evidence");
                    Check(report.StoredChecksumHex == expectedField.ToUpperInvariant() && report.ComputedChecksumHex == expectedField.ToUpperInvariant(),
                        "Native finalized field disagrees");
                    Check(report.ChecksPass && report.BigEndianWordSum == 0, "Pinned native corpus rejected");
                    Blocked(report);
                });
                if (fromExportDiff) reconstructed++; else corpus++;
            }
            if (corpus == 0) Console.WriteLine("SKIP native corpus: no explicitly pinned local paths supplied.");
            Console.WriteLine("PASS " + passed + " checks; " + corpus + " pinned native corpus files and " + reconstructed + " native-export diff reconstructions. No transport or writer linked.");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception.Message);
            return 1;
        }
    }
}

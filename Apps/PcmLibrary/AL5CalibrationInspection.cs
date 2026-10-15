// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Security.Cryptography;

namespace PcmHacking
{
    /// <summary>File-byte checks only. No controller, transport, or programming operations.</summary>
    public static class AL5CalibrationInspection
    {
        public const int StartAddress = 0x08000;
        public const int EndAddressExclusive = 0x15FD8;
        public const int ChecksumAddress = 0x15FD4;
        public const int Length = EndAddressExclusive - StartAddress;
        public const string Scope = "Checksum and anchors validated offline for OS 15184109 / calibration 15183960. File checks do not verify live identity, edit authorization, programming or recovery.";

        public static AL5CalibrationFileReport Inspect(byte[] image)
        {
            if (image == null) throw new ArgumentNullException(nameof(image));
            // Reject unsupported containers/full images before copying or scanning their contents.
            if (image.Length != Length) return InvalidLength(image.Length);
            return InspectSnapshot((byte[])image.Clone());
        }

        public static AL5CalibrationComparisonReport Compare(byte[] baseline, byte[] candidate)
        {
            if (baseline == null) throw new ArgumentNullException(nameof(baseline));
            if (candidate == null) throw new ArgumentNullException(nameof(candidate));
            byte[]? before = baseline.Length == Length ? (byte[])baseline.Clone() : null;
            byte[]? after = candidate.Length == Length ? (byte[])candidate.Clone() : null;
            AL5CalibrationFileReport baselineReport = before == null ? InvalidLength(baseline.Length) : InspectSnapshot(before);
            AL5CalibrationFileReport candidateReport = after == null ? InvalidLength(candidate.Length) : InspectSnapshot(after);
            var ranges = new List<AL5CalibrationDiffRange>();
            int changed = 0;
            if (before != null && after != null)
            {
                int offset = 0;
                while (offset < Length)
                {
                    if (before[offset] == after[offset]) { offset++; continue; }
                    int first = offset;
                    while (offset < Length && before[offset] != after[offset]) offset++;
                    ranges.Add(new AL5CalibrationDiffRange(StartAddress + first, offset - first));
                    changed += offset - first;
                }
            }
            return new AL5CalibrationComparisonReport(baselineReport, candidateReport, ranges, changed);
        }

        private static AL5CalibrationFileReport InvalidLength(int actualLength)
        {
            return new AL5CalibrationFileReport(actualLength, null, false, null, null, null, null,
                new List<string> { "Length " + actualLength + "; expected exactly " + Length + " raw calibration bytes." });
        }

        private static AL5CalibrationFileReport InspectSnapshot(byte[] image)
        {
            var errors = new List<string>();
            bool anchors = true;
            CheckAnchor(image, 0x08024, new byte[] { 0x00, 0xE7, 0xB0, 0x58 }, errors, ref anchors);
            CheckAnchor(image, 0x0A996, new byte[] { 0x11, 0xF7, 0x0C, 0x68, 0x07, 0x3E, 0x05, 0xA0, 0x04, 0x00, 0x02, 0xD9 }, errors, ref anchors);
            CheckAnchor(image, 0x158A8, new byte[] { 0x00, 0x11, 0x00, 0x09 }, errors, ref anchors);

            ushort crc = 0;
            int bodyLength = ChecksumAddress - StartAddress;
            for (int offset = 0; offset < bodyLength; offset++)
            {
                crc ^= image[offset];
                for (int bit = 0; bit < 8; bit++)
                    crc = (ushort)((crc >> 1) ^ ((crc & 1) != 0 ? 0xA001 : 0));
            }
            ushort bodySum = WordSum(image, bodyLength);
            ushort compensation = unchecked((ushort)(-bodySum - crc));
            ushort sum = WordSum(image, image.Length);
            string computed = crc.ToString("X4") + compensation.ToString("X4");
            string stored = ReadWord(image, bodyLength).ToString("X4") + ReadWord(image, bodyLength + 2).ToString("X4");
            bool nativeValid = stored == computed;
            if (!nativeValid) errors.Add("Native CRC16/compensation field does not match the validated formula.");
            if (sum != 0) errors.Add("Big-endian word-sum invariant failed.");
            string hash;
            using (SHA256 sha = SHA256.Create())
                hash = BitConverter.ToString(sha.ComputeHash(image)).Replace("-", "").ToLowerInvariant();
            return new AL5CalibrationFileReport(image.Length, hash, anchors, nativeValid, stored, computed, sum, errors);
        }

        private static ushort ReadWord(byte[] image, int offset)
        {
            return (ushort)((image[offset] << 8) | image[offset + 1]);
        }

        private static ushort WordSum(byte[] image, int count)
        {
            uint sum = 0;
            for (int offset = 0; offset < count; offset += 2)
                sum = (sum + ReadWord(image, offset)) & 0xFFFF;
            return (ushort)sum;
        }

        private static void CheckAnchor(byte[] image, int address, byte[] expected, List<string> errors, ref bool anchors)
        {
            int offset = address - StartAddress;
            for (int index = 0; index < expected.Length; index++)
            {
                if (image[offset + index] == expected[index]) continue;
                anchors = false;
                errors.Add("Known-family anchor mismatch at 0x" + address.ToString("X5") + ".");
                return;
            }
        }
    }

    public sealed class AL5CalibrationFileReport
    {
        internal AL5CalibrationFileReport(int actualLength, string? sha256, bool anchors, bool? checksum,
            string? stored, string? computed, ushort? sum, List<string> errors)
        {
            ActualLength = actualLength;
            Sha256 = sha256;
            KnownFamilyAnchorsMatch = anchors;
            NativeChecksumValid = checksum;
            StoredChecksumHex = stored;
            ComputedChecksumHex = computed;
            BigEndianWordSum = sum;
            InputErrors = new ReadOnlyCollection<string>(new List<string>(errors));
        }
        public int ActualLength { get; }
        public bool HasExactLength => ActualLength == AL5CalibrationInspection.Length;
        public string? Sha256 { get; }
        public bool KnownFamilyAnchorsMatch { get; }
        public bool? NativeChecksumValid { get; }
        public string? StoredChecksumHex { get; }
        public string? ComputedChecksumHex { get; }
        public ushort? BigEndianWordSum { get; }
        public IReadOnlyList<string> InputErrors { get; }
        public bool ChecksPass => HasExactLength && InputErrors.Count == 0;
        public bool LiveIdentityVerified => false;
        public bool EditsAuthorizedForWriting => false;
        public bool LiveWriteEnabled => false;
        public bool ReadyToFlash => false;
    }

    public sealed class AL5CalibrationDiffRange
    {
        internal AL5CalibrationDiffRange(int startAddress, int length)
        {
            StartAddress = startAddress;
            Length = length;
        }
        public int StartAddress { get; }
        public int EndAddressInclusive => StartAddress + Length - 1;
        public int Length { get; }
    }

    public sealed class AL5CalibrationComparisonReport
    {
        internal AL5CalibrationComparisonReport(AL5CalibrationFileReport baseline, AL5CalibrationFileReport candidate,
            List<AL5CalibrationDiffRange> ranges, int changedByteCount)
        {
            Baseline = baseline;
            Candidate = candidate;
            DiffRanges = new ReadOnlyCollection<AL5CalibrationDiffRange>(new List<AL5CalibrationDiffRange>(ranges));
            ChangedByteCount = changedByteCount;
        }
        public AL5CalibrationFileReport Baseline { get; }
        public AL5CalibrationFileReport Candidate { get; }
        public IReadOnlyList<AL5CalibrationDiffRange> DiffRanges { get; }
        public bool DifferencesComputed => Baseline.HasExactLength && Candidate.HasExactLength;
        public int ChangedByteCount { get; }
        public bool FileChecksPass => Baseline.ChecksPass && Candidate.ChecksPass;
        public string Scope => AL5CalibrationInspection.Scope;
        public bool LiveIdentityVerified => false;
        public bool EditsAuthorizedForWriting => false;
        public bool LiveWriteEnabled => false;
        public bool ReadyToFlash => false;
    }
}

// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    /// <summary>Offline decoder for already captured AL5 program requests; no sender or packet builder.</summary>
    public sealed class AL5CapturedProgramImage
    {
        public const int StartAddress = 0x8000;
        public const int EndAddressExclusive = 0x1FFFE;
        public const int ObservedMaximumBlockBytes = 512;
        private readonly byte[] image = new byte[EndAddressExclusive - StartAddress];
        private readonly bool[] covered = new bool[EndAddressExclusive - StartAddress];
        public int CoveredBytes { get; private set; }
        public int AcceptedRequests { get; private set; }
        public bool Complete => CoveredBytes == image.Length;
        public bool LiveWriteEnabled => false;
        public bool RecoveryVerified => false;

        // Input excludes physical VPW CRC, as in EFILive host wrappers.
        // Validate the entire request and all overlaps before mutating owned state.
        public void Observe(byte[] request)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));
            if (request.Length < 14 || request.Length > ObservedMaximumBlockBytes + 12)
                throw new ArgumentException("Captured request exceeds bounded profile.", nameof(request));
            byte[] data = (byte[])request.Clone();
            if (data[0] != 0x6D || data[1] != 0x18 || data[2] != 0xF0 || data[3] != 0x36 || data[4] != 0)
                throw new ArgumentException("Expected a captured AL5 subtype-zero program request.", nameof(request));
            int count = (data[5] << 8) | data[6];
            int address = (data[7] << 16) | (data[8] << 8) | data[9];
            if (count != data.Length - 12 || count % 2 != 0 || address % 2 != 0 ||
                address < StartAddress || address + count > EndAddressExclusive)
                throw new ArgumentException("Captured length, alignment or address is outside the observed profile.", nameof(request));
            int sum = 0;
            for (int i = 4; i < data.Length - 2; i++) sum = (sum + data[i]) & 0xFFFF;
            if (sum != ((data[data.Length-2] << 8) | data[data.Length-1]))
                throw new ArgumentException("Captured transfer byte sum mismatch.", nameof(request));
            int offset = address - StartAddress;
            for (int i = 0; i < count; i++)
                if (covered[offset+i] && image[offset+i] != data[10+i])
                    throw new ArgumentException("Conflicting captured overlap; existing evidence retained.", nameof(request));
            for (int i = 0; i < count; i++)
            {
                if (!covered[offset+i]) { covered[offset+i] = true; CoveredBytes++; }
                image[offset+i] = data[10+i];
            }
            AcceptedRequests++;
        }

        public byte[] CopyCompleteImage()
        {
            if (!Complete) throw new InvalidOperationException("Incomplete capture; missing bytes cannot be invented.");
            return (byte[])image.Clone();
        }

        public AL5ProgrammingAssessment AssessReference(byte[] calibration, byte[] collateral)
        {
            // The marker word is not transferred. Never synthesize it or present this as a saved flash snapshot.
            if (!Complete) throw new InvalidOperationException("Incomplete captured program image.");
            if (calibration == null || collateral == null) throw new ArgumentNullException();
            if (calibration.Length != AL5CalibrationInspection.Length || collateral.Length != AL5ProgrammingWorkflow.CollateralLength)
                throw new ArgumentException("Exact independent calibration and collateral references required.");
            for (int i = 0; i < image.Length; i++)
                if (image[i] != (i < calibration.Length ? calibration[i] : collateral[i-calibration.Length]))
                    throw new ArgumentException("Captured bytes differ from supplied references.");
            return AL5ProgrammingWorkflow.Assess(calibration, collateralBackup: collateral);
        }
    }
}

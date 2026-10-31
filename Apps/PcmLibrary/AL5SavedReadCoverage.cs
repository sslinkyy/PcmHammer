// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    /// <summary>Offline layout of saved reads. Does not extend the live Mode 23 reader.</summary>
    public static class AL5SavedReadCoverage
    {
        public const int SupplementStart = AL5CalibrationInspection.EndAddressExclusive;
        public const int SupplementEndExclusive = AL5ProgrammingWorkflow.SnapshotEndExclusive;
        public const int SupplementLength = SupplementEndExclusive - SupplementStart;
        public const int DwordBytes = 4;
        public const int SupplementalDwordCount = SupplementLength / DwordBytes;
        public const int LastDwordAddress = SupplementEndExclusive - DwordBytes;
        public static bool ExtendedLiveReadEnabled => false;
        public static bool SupplementalReadabilityProven => false;

        public static byte[] AssembleSavedSnapshot(byte[] calibration, byte[] supplement)
        {
            if(calibration==null || supplement==null)throw new ArgumentNullException();
            if(calibration.Length!=AL5CalibrationInspection.Length || supplement.Length!=SupplementLength)
                throw new ArgumentException("Exact 57,304-byte calibration and 41,000-byte supplement required.");
            var snapshot=new byte[AL5ProgrammingWorkflow.SnapshotLength];
            Buffer.BlockCopy(calibration,0,snapshot,0,calibration.Length);
            Buffer.BlockCopy(supplement,0,snapshot,calibration.Length,supplement.Length);
            // Retain supplied marker bytes, even when wrong. Never replace with expected 4AFC.
            return snapshot;
        }
    }
}

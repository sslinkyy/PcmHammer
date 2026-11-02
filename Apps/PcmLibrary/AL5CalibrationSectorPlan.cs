// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    /// <summary>Datasheet geometry under the candidate contiguous x16 CPU byte mapping. No bus-cycle or device API.</summary>
    public sealed class AL5FlashSector
    {
        internal AL5FlashSector(int index, uint start, uint end) { Index=index; Start=start; EndExclusive=end; }
        public int Index { get; }
        public uint Start { get; }
        public uint EndExclusive { get; }
        public uint ByteCount => EndExclusive-Start;
    }

    /// <summary>Calibration-only destination policy and explicit saved-sector preservation. Never live authority.</summary>
    public sealed class AL5CalibrationSectorPlan
    {
        public const int SectorCount=19;
        public const uint FlashEndExclusive=0x100000;
        public const uint CalibrationEraseStart=0x8000, CalibrationEraseEndExclusive=0x20000;
        private readonly byte[] candidate, before;
        public bool PhysicalSectorMappingVerified => false;
        public bool IndependentBackupVerified => false;
        public bool LiveUploadEnabled => false;
        public bool LiveExecutionEnabled => false;
        public bool LiveWriteEnabled => false;
        public bool ReadyToFlash => false;
        public bool RecoveryVerified => false;
        public ushort SavedOriginalMarker => (ushort)((before[before.Length-2]<<8)|before[before.Length-1]);

        public static AL5FlashSector Sector(int index)
        {
            if(index<0 || index>=SectorCount)throw new ArgumentOutOfRangeException(nameof(index));
            switch(index)
            {
                case 0:return new AL5FlashSector(0,0,0x4000);
                case 1:return new AL5FlashSector(1,0x4000,0x6000);
                case 2:return new AL5FlashSector(2,0x6000,0x8000);
                case 3:return new AL5FlashSector(3,0x8000,0x10000);
                default:uint start=(uint)(index-3)*0x10000;return new AL5FlashSector(index,start,start+0x10000);
            }
        }

        public static uint[] CopyCalibrationEraseSectorStarts() => new uint[]{Sector(3).Start,Sector(4).Start};

        public static void ValidateSectorErase(uint sectorStart)
        {
            // Canonical starts only. A high address inside a sector is not an independently selected scope.
            if(sectorStart!=Sector(3).Start && sectorStart!=Sector(4).Start)
                throw new ArgumentOutOfRangeException(nameof(sectorStart),"Calibration profile permits only SA3 and SA4.");
        }

        public static void ValidateChipErase()
        { throw new InvalidOperationException("Chip erase is forbidden by the calibration-only profile."); }

        public static void ValidateProgramSpan(uint cpuByteAddress, int byteCount)
        {
            // These are final array destinations, never AMD unlock-cycle or loader RAM addresses.
            if(byteCount<=0 || (byteCount&1)!=0 || (cpuByteAddress&1)!=0 ||
                cpuByteAddress<CalibrationEraseStart ||
                (ulong)cpuByteAddress+(uint)byteCount>AL5ProgrammingWorkflow.MarkerAddress)
                throw new ArgumentOutOfRangeException(nameof(cpuByteAddress),"Whole aligned span must stay in 8000..1FFFD; finalization is separate.");
        }

        public static void ValidateFinalizationSpan(uint cpuByteAddress, int byteCount)
        {
            if(cpuByteAddress!=AL5ProgrammingWorkflow.MarkerAddress || byteCount!=2)
                throw new ArgumentOutOfRangeException(nameof(cpuByteAddress),"Only the exact completion-marker word belongs to finalization.");
        }

        public AL5CalibrationSectorPlan(byte[] calibration, byte[] savedPreEraseSectors)
        {
            if(calibration==null || savedPreEraseSectors==null)throw new ArgumentNullException();
            if(calibration.Length!=AL5CalibrationInspection.Length || savedPreEraseSectors.Length!=AL5ProgrammingWorkflow.SnapshotLength)
                throw new ArgumentException("Exact calibration and all 98,304 pre-erase sector bytes are required, including the original marker.");
            candidate=(byte[])calibration.Clone();before=(byte[])savedPreEraseSectors.Clone();
            if(!AL5CalibrationInspection.Inspect(candidate).ChecksPass)
                throw new ArgumentException("Candidate native checksum and anchors must pass.");
            ValidateProgramSpan(AL5CalibrationInspection.StartAddress,candidate.Length);
            ValidateFinalizationSpan(AL5ProgrammingWorkflow.MarkerAddress,2);
        }

        public byte[] CopySavedPreEraseSectors() => (byte[])before.Clone();
        public byte[] CopyCollateralBackup()
        {
            var bytes=new byte[AL5ProgrammingWorkflow.CollateralLength];
            Array.Copy(before,candidate.Length,bytes,0,bytes.Length);return bytes;
        }

        /// <summary>Desired file bytes only; all collateral and the original marker remain explicit.</summary>
        public byte[] CopyDesiredBeforeFinalization()
        {
            var bytes=(byte[])before.Clone();Array.Copy(candidate,bytes,candidate.Length);return bytes;
        }

        public AL5ProgrammingAssessment AssessSavedReadback(byte[] savedReadback) =>
            AL5ProgrammingWorkflow.Assess(candidate,savedReadback,CopyCollateralBackup());
    }
}

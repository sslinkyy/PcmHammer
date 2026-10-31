// SPDX-License-Identifier: GPL-3.0-only
using System;
namespace PcmHacking
{
    /// <summary>Conditional byte mapping for saved SPS modules; never a flashable full image.</summary>
    public sealed class AL5SpsModuleMapping
    {
        private readonly byte[] os, calibration;
        public uint OsStart => 0x20000;
        public uint OsEndInclusive => 0xC5F93;
        public uint CalibrationStart => 0x8000;
        public uint CalibrationEndInclusive => 0x15FD7;
        public bool LiveWriteEnabled => false;
        public bool ReadyToFlash => false;
        public bool PhysicalSectorMappingVerified => false;
        public AL5SpsModuleMapping(byte[] os, byte[] calibration)
        {
            if(os==null || calibration==null)throw new ArgumentNullException();
            if(os.Length!=679828 || calibration.Length!=57304)throw new ArgumentException("Exact expanded SPS module lengths required; no guessed BIN offsets.");
            this.os=(byte[])os.Clone(); this.calibration=(byte[])calibration.Clone();
            if(Word(this.os,0x22)!=1 || Word(this.calibration,0x22)!=2 ||
               Long(this.os,0x3E)!=OsStart || Long(this.os,0x42)!=OsEndInclusive ||
               Long(this.os,0x46)!=CalibrationStart || Long(this.os,0x4A)!=CalibrationEndInclusive)
                throw new ArgumentException("Unqualified SPS module type or destination metadata.");
            if(Sum(this.os)!=0 || !AL5CalibrationInspection.Inspect(this.calibration).ChecksPass)
                throw new ArgumentException("OS word sum or calibration native checksum/anchor validation failed.");
        }
        internal static int Word(byte[] b,int i)=>(b[i]<<8)|b[i+1];
        private static uint Long(byte[] b,int i)=>((uint)b[i]<<24)|((uint)b[i+1]<<16)|((uint)b[i+2]<<8)|b[i+3];
        internal static ushort Sum(byte[] b) {int sum=0;for(int i=0;i<b.Length;i+=2)sum=(sum+Word(b,i))&65535;return (ushort)sum;}
        public byte[] CopyOsModule()=>(byte[])os.Clone();
        public byte[] CopyCalibrationModule()=>(byte[])calibration.Clone();
        /// <summary>Predicted bytes at 0x8000..0xFFFFF only; unknown low flash is deliberately absent.</summary>
        public byte[] CopyConditionalAffectedBytes()
        {
            var result=new byte[0xF8000];
            // Firmware fills tails with 4AFC, not staging zero padding.
            for(int i=0;i<result.Length;i+=2){result[i]=0x4A;result[i+1]=0xFC;}
            Array.Copy(calibration,0,result,0,calibration.Length);
            Array.Copy(os,0,result,0x20000-0x8000,os.Length);
            return result;
        }
        /// <summary>Both inputs must be explicit saved raw 1 MiB snapshots. No freshness is inferred.</summary>
        public AL5SpsPreservationComparison CompareSavedSnapshots(byte[] before,byte[] after)
        {
            if(before==null || after==null)throw new ArgumentNullException();
            if(before.Length!=0x100000 || after.Length!=0x100000)throw new ArgumentException("Full saved snapshots required; calibration BINs do not establish preservation.");
            before=(byte[])before.Clone();after=(byte[])after.Clone();var expected=CopyConditionalAffectedBytes();
            return new AL5SpsPreservationComparison(Diff(before,after,0,0,0x4000),Diff(before,after,0x4000,0x4000,0x4000),
                Diff(before,expected,0x15FD8,0x15FD8-0x8000,0x20000-0x15FD8),
                Diff(before,expected,0xC5F94,0xC5F94-0x8000,0x100000-0xC5F94),Diff(after,expected,0x8000,0,expected.Length));
        }
        private static int Diff(byte[] a,byte[] b,int ai,int bi,int n){int different=0;for(int i=0;i<n;i++)if(a[ai+i]!=b[bi+i])different++;return different;}
    }
    public sealed class AL5SpsPreservationComparison
    {
        internal AL5SpsPreservationComparison(int boot,int banks,int lowTail,int highTail,int affected)
        {BootRegionDifferences=boot;PersistentRegionDifferences=banks;LowerTailBytesReplacedByFill=lowTail;UpperTailBytesReplacedByFill=highTail;AffectedImageDifferences=affected;}
        public int BootRegionDifferences {get;}
        public int PersistentRegionDifferences {get;}
        public int LowerTailBytesReplacedByFill {get;}
        public int UpperTailBytesReplacedByFill {get;}
        public int AffectedImageDifferences {get;}
        public bool SavedProtectedPrefixMatches => BootRegionDifferences==0 && PersistentRegionDifferences==0;
        public bool SavedAffectedImageMatches => AffectedImageDifferences==0;
        public bool OtherFlashWouldChange => LowerTailBytesReplacedByFill!=0 || UpperTailBytesReplacedByFill!=0;
        public bool PhysicalPreservationVerified => false;
        public bool LiveWriteEnabled => false;
        public bool ReadyToFlash => false;
    }
}

// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Security.Cryptography;

namespace PcmHacking
{
    public enum AL5SpsOfflineState { LoaderRequest, LoaderReply, BlockRequest, BlockReply, CompletedObservations, Stopped }

    /// <summary>Saved SPS observations only. No transport, packet construction or retry authority.</summary>
    public sealed class AL5SpsOfflineRehearsal
    {
        private readonly byte[] loader, os, calibration;
        private int module, block;
        public AL5SpsOfflineState State { get; private set; } = AL5SpsOfflineState.LoaderRequest;
        public int AcknowledgedBlocks { get; private set; }
        public int PendingReplies { get; private set; }
        public byte? FailureStatus { get; private set; }
        public string StopReason { get; private set; } = "";
        public bool LiveWriteEnabled => false;
        public bool ReadyToFlash => false;
        public bool AutomaticRetryEnabled => false;
        public bool RecoveryVerified => false;
        public bool PhysicalReadbackVerified => false;
        public uint OsStart { get; }
        public uint OsEndInclusive { get; }
        public uint CalibrationStart { get; }
        public uint CalibrationEndInclusive { get; }
        public uint OsFillStart => OsEndInclusive + 1;
        public uint OsFillEndExclusive => 0x100000;
        public uint CalibrationFillStart => CalibrationEndInclusive + 1;
        public uint CalibrationFillEndExclusive => 0x20000;
        public ushort FillWord => 0x4AFC;
        public ushort SavedOsWordSum { get; }
        public ushort SavedCalibrationWordSum { get; }
        // Literal erase command addresses from 0xFF9C50/0xFF9D7C; not a physical sector map or send plan.
        public uint[] CopyObservedOsModuleEraseAddresses() => new uint[]
            {0xF0000,0xE0000,0xD0000,0xC0000,0xB0000,0xA0000,0x90000,0x80000,
             0x70000,0x60000,0x50000,0x40000,0x30000,0x20000,0x10000,0x8000};
        public uint[] CopyObservedCalibrationModuleEraseAddresses() => new uint[] {0x10000,0x8000};
        private static ushort Sum(byte[] data)
        {
            int sum=0;for(int i=0;i<data.Length;i+=2)sum=(sum+Word(data,i))&65535;
            return (ushort)sum;
        }

        public AL5SpsOfflineRehearsal(byte[] loader, string loaderSha256, byte[] os, byte[] calibration)
        {
            if(loader==null || os==null || calibration==null) throw new ArgumentNullException();
            if(loader.Length!=3858 || os.Length!=679828 || calibration.Length!=57304)
                throw new ArgumentException("Outside observed SPS 15107661/15184109/15183960 profile.");
            using(var hash=SHA256.Create())
            {
                var actual=BitConverter.ToString(hash.ComputeHash(loader)).Replace("-", "").ToLowerInvariant();
                if(!String.Equals(actual,loaderSha256,StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException("Saved loader identity mismatch.");
            }
            this.loader=(byte[])loader.Clone(); this.os=(byte[])os.Clone(); this.calibration=(byte[])calibration.Clone();
            if(Word(os,0x22)!=1 || Word(calibration,0x22)!=2) throw new ArgumentException("Unexpected module types.");
            SavedOsWordSum=Sum(this.os); SavedCalibrationWordSum=Sum(this.calibration);
            if(SavedOsWordSum!=0 || SavedCalibrationWordSum!=0) throw new ArgumentException("Saved module word-sum verification failed.");
            OsStart=Long(os,0x3E); OsEndInclusive=Long(os,0x42);
            CalibrationStart=Long(os,0x46); CalibrationEndInclusive=Long(os,0x4A);
            if(OsStart!=0x20000 || OsEndInclusive!=0xC5F93 || CalibrationStart!=0x8000 || CalibrationEndInclusive!=0x15FD7)
                throw new ArgumentException("Unqualified flash destination metadata.");
        }
        private static int Word(byte[] m,int p) => (m[p]<<8)|m[p+1];
        private static uint Long(byte[] m,int p) => ((uint)m[p]<<24)|((uint)m[p+1]<<16)|((uint)m[p+2]<<8)|m[p+3];
        private static void Equal(byte[] m,int offset,byte[] expected,int start,int length)
        {
            for(int i=0;i<length;i++) if(m[offset+i]!=expected[start+i]) throw new ArgumentException("Saved payload mismatch.");
        }
        public void ObserveRequest(byte[] m)
        {
            if(m==null) throw new ArgumentNullException(nameof(m));
            if(State!=AL5SpsOfflineState.LoaderRequest && State!=AL5SpsOfflineState.BlockRequest)
                throw new InvalidOperationException("No request slot; pending, stopped or completed observations cannot retry implicitly.");
            bool entry=State==AL5SpsOfflineState.LoaderRequest;
            int count=entry?3858:4096;
            if(m.Length!=count+12 || m[0]!=0x6D || m[1]!=0x18 || m[2]!=0xF0 || m[3]!=0x36 ||
               m[4]!=(entry?0x80:0) || Word(m,5)!=count || LongAddress(m)!=(entry?0xFF9006:0xFF8000))
                throw new ArgumentException("Unexpected saved SPS block envelope.");
            int sum=0; for(int i=4;i<m.Length-2;i++) sum+=m[i];
            if((sum&65535)!=Word(m,m.Length-2)) throw new ArgumentException("Saved block checksum mismatch.");
            if(entry) Equal(m,10,loader,0,count);
            else
            {
                var source=module==0?os:calibration; int start=block*4096;
                int n=Math.Min(4096,source.Length-start); Equal(m,10,source,start,n);
                for(int i=n;i<4096;i++) if(m[10+i]!=0) throw new ArgumentException("Nonzero final-block padding.");
            }
            State=entry?AL5SpsOfflineState.LoaderReply:AL5SpsOfflineState.BlockReply;
        }
        private static int LongAddress(byte[] m) => (m[7]<<16)|(m[8]<<8)|m[9];
        public void ObserveReply(byte[] m)
        {
            if(m==null) throw new ArgumentNullException(nameof(m));
            bool entry=State==AL5SpsOfflineState.LoaderReply;
            if(!entry && State!=AL5SpsOfflineState.BlockReply) throw new InvalidOperationException("No pending reply owner.");
            if(m.Length!=6 || m[0]!=0x6C || m[1]!=0xF0 || m[2]!=0x18 || m[3]!=0x76 || m[4]!=(entry?0x80:0))
                throw new ArgumentException("Unexpected saved loader reply.");
            byte status=m[5];
            if(!entry && status==0x78) { PendingReplies++; return; }
            if(status==0x74 || status==0x75 || status==0x77 || status==0x85 || status==0x8A)
            {
                FailureStatus=status; StopReason="Saved loader failure; no automatic retry or recovery authority.";
                State=AL5SpsOfflineState.Stopped; return;
            }
            if(entry)
            {
                if(status!=0x73) { Stop("Unexpected loader-entry status."); return; }
                State=AL5SpsOfflineState.BlockRequest;return;
            }
            var source=module==0?os:calibration;
            bool last=(block+1)*4096>=source.Length;
            byte expected=module==1 && last?(byte)0x86:(byte)0x73;
            if(status!=expected) { Stop("Terminal status does not match pending module boundary.");return; }
            AcknowledgedBlocks++; block++;
            if(last) {module++;block=0;}
            State=module==2?AL5SpsOfflineState.CompletedObservations:AL5SpsOfflineState.BlockRequest;
        }
        private void Stop(string why) { StopReason=why; State=AL5SpsOfflineState.Stopped; }
        public void Interrupt()
        {
            if(State==AL5SpsOfflineState.CompletedObservations || State==AL5SpsOfflineState.Stopped)
                throw new InvalidOperationException("Attempt already closed.");
            Stop("Saved interruption: physical outcome and recovery unknown; create a new rehearsal.");
        }
    }
}

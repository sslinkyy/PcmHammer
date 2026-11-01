// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    public enum AL5SpsOfflineState { LoaderRequest, LoaderReply, BlockRequest, BlockReply, CompletedObservations, Stopped }

    /// <summary>Offline SPS plan and saved-reply validation. No transport or retry authority.</summary>
    public sealed class AL5SpsOfflineRehearsal
    {
        private readonly AL5SpsOfflineWritePlan plan;
        private int nextRequest;
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
        public uint OsStart => plan.OsStart;
        public uint OsEndInclusive => plan.OsEndInclusive;
        public uint CalibrationStart => plan.CalibrationStart;
        public uint CalibrationEndInclusive => plan.CalibrationEndInclusive;
        public uint OsFillStart => OsEndInclusive + 1;
        public uint OsFillEndExclusive => 0x100000;
        public uint CalibrationFillStart => CalibrationEndInclusive + 1;
        public uint CalibrationFillEndExclusive => 0x20000;
        public ushort FillWord => 0x4AFC;
        public ushort SavedOsWordSum => plan.SavedOsWordSum;
        public ushort SavedCalibrationWordSum => plan.SavedCalibrationWordSum;
        // Literal erase command addresses from 0xFF9C50/0xFF9D7C; not a physical sector map or send plan.
        public uint[] CopyObservedOsModuleEraseAddresses() => new uint[]
            {0xF0000,0xE0000,0xD0000,0xC0000,0xB0000,0xA0000,0x90000,0x80000,
             0x70000,0x60000,0x50000,0x40000,0x30000,0x20000,0x10000,0x8000};
        public uint[] CopyObservedCalibrationModuleEraseAddresses() => new uint[] {0x10000,0x8000};


        public AL5SpsOfflineRehearsal(byte[] loader, string loaderSha256, byte[] os, byte[] calibration)
        {
            plan=new AL5SpsOfflineWritePlan(loader,loaderSha256,os,calibration);
        }
        /// <summary>Copy for offline review only; does not send or mark an operation pending.</summary>
        public byte[] CopyNextOfflineRequest()
        {
            if(State!=AL5SpsOfflineState.LoaderRequest && State!=AL5SpsOfflineState.BlockRequest)
                throw new InvalidOperationException("No offline request slot.");
            return plan.CopyRequest(nextRequest);
        }
        public void ObserveRequest(byte[] m)
        {
            if(m==null) throw new ArgumentNullException(nameof(m));
            if(State!=AL5SpsOfflineState.LoaderRequest && State!=AL5SpsOfflineState.BlockRequest)
                throw new InvalidOperationException("No request slot; pending, stopped or completed observations cannot retry implicitly.");
            bool entry=State==AL5SpsOfflineState.LoaderRequest;
            if(!plan.Matches(nextRequest,m))
                throw new ArgumentException("Saved request differs from the validated offline SPS plan.");
            State=entry?AL5SpsOfflineState.LoaderReply:AL5SpsOfflineState.BlockReply;
        }
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
                nextRequest++;State=AL5SpsOfflineState.BlockRequest;return;
            }
            byte expected=nextRequest==plan.RequestCount-1?(byte)0x86:(byte)0x73;
            if(status!=expected) { Stop("Terminal status does not match pending module boundary.");return; }
            AcknowledgedBlocks++;nextRequest++;
            State=nextRequest==plan.RequestCount?AL5SpsOfflineState.CompletedObservations:AL5SpsOfflineState.BlockRequest;
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

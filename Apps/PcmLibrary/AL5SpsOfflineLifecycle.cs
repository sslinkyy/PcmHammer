// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    public enum AL5SpsOfflinePhase { Setup, Programming, Cleanup, CompletedObservations, Stopped }
    public enum AL5SpsSavedFrameDisposition { Advanced, Pending, KeepAlive, Unrelated, Rejected }

    /// <summary>Ordered saved SPS setup/program/cleanup observations. No device or security-key generator.</summary>
    public sealed class AL5SpsOfflineLifecycle
    {
        private readonly AL5SpsOfflineRehearsal program;
        private int exchange;
        // Dynamic seed/key bytes are deliberately opaque; these rules confer no security authorization.
        private static readonly (bool Tx,string Prefix,int Length)[] Setup = {
            (true,"6cfef02800",5),(false,"6cf0186800",5),
            (true,"6c18f02701",5),(false,"6cf0186701",7),
            (true,"6c18f02702",7),(false,"6cf018670234",6),
            (true,"6cfef02800",5),(false,"6cf0186800",5),
            (true,"6c18f034",4),(false,"6cf0187444",5),
            (true,"6cfef0a0",4),(false,"6cf018e0aa",5),
            (true,"6cfef0a1",4),(true,"6c18f034",4),(false,"6cf0187444",5)};
        private static readonly (bool Tx,string Prefix,int Length)[] Cleanup = {
            (true,"6cfef02800",5),(false,"6cf0186800",5),
            (true,"6c18f02701",5),(false,"6cf018670137",6),
            (true,"6c18f02701",5),(false,"6cf0186701",7),
            (true,"6c18f02702",7),(false,"6cf018670234",6),
            (true,"6cfef02800",5),(false,"6cf0186800",5)};
        public AL5SpsOfflinePhase Phase { get; private set; } = AL5SpsOfflinePhase.Setup;
        public int SetupObservations { get; private set; }
        public int CleanupObservations { get; private set; }
        public int KeepAlives { get; private set; }
        public int UnrelatedReplies { get; private set; }
        public int AcknowledgedBlocks => program.AcknowledgedBlocks;
        public int PendingReplies => program.PendingReplies;
        public string StopReason { get; private set; } = "";
        public bool LiveUploadEnabled => false;
        public bool LiveExecutionEnabled => false;
        public bool LiveWriteEnabled => false;
        public bool ReadyToFlash => false;
        public bool SecurityAuthorizationProven => false;
        public bool PhysicalReadbackVerified => false;
        public bool RecoveryVerified => false;
        public bool IdentityWritesEnabled => false;
        public bool AutomaticRetryEnabled => false;

        public AL5SpsOfflineLifecycle(byte[] loader,string loaderSha256,byte[] os,byte[] calibration)
        {program=new AL5SpsOfflineRehearsal(loader,loaderSha256,os,calibration);}

        public byte[] CopyNextOfflineProgrammingRequest()
        {
            if(Phase!=AL5SpsOfflinePhase.Programming)throw new InvalidOperationException("Setup must precede offline programming review.");
            return program.CopyNextOfflineRequest();
        }

        private static bool Matches(byte[] m,string prefix,int length)
        {
            if(m.Length!=length)return false;
            return BitConverter.ToString(m).Replace("-", "").StartsWith(prefix,StringComparison.OrdinalIgnoreCase);
        }
        private static bool FromAl5(byte[] m) => (m[0]==0x6C || m[0]==0x6D) && m[1]==0xF0 && m[2]==0x18;
        private AL5SpsSavedFrameDisposition Reject(string why)
        {
            StopReason=why;Phase=AL5SpsOfflinePhase.Stopped;
            if(program.State!=AL5SpsOfflineState.Stopped && program.State!=AL5SpsOfflineState.CompletedObservations)program.Interrupt();
            return AL5SpsSavedFrameDisposition.Rejected;
        }

        public AL5SpsSavedFrameDisposition ObserveSavedFrame(bool transmitted,byte[] message)
        {
            if(Phase==AL5SpsOfflinePhase.CompletedObservations || Phase==AL5SpsOfflinePhase.Stopped)
                throw new InvalidOperationException("Saved lifecycle is closed.");
            if(message==null)throw new ArgumentNullException(nameof(message));
            // Largest observed profile request is a 4096-byte block plus its 12-byte envelope.
            if(message.Length<4 || message.Length>4108)return Reject("Saved frame outside observed profile bounds.");
            var m=(byte[])message.Clone();
            if(transmitted && Matches(m,"8cfef03f",4)){KeepAlives++;return AL5SpsSavedFrameDisposition.KeepAlive;}
            if(!transmitted && !FromAl5(m)){UnrelatedReplies++;return AL5SpsSavedFrameDisposition.Unrelated;}
            if(Phase==AL5SpsOfflinePhase.Setup || Phase==AL5SpsOfflinePhase.Cleanup)
            {
                var rules=Phase==AL5SpsOfflinePhase.Setup?Setup:Cleanup;var rule=rules[exchange];
                if(transmitted!=rule.Tx || !Matches(m,rule.Prefix,rule.Length))return Reject("Unexpected saved AL5 setup/cleanup exchange.");
                if(Phase==AL5SpsOfflinePhase.Setup)SetupObservations++;else CleanupObservations++;
                if(++exchange==rules.Length)
                {exchange=0;Phase=Phase==AL5SpsOfflinePhase.Setup?AL5SpsOfflinePhase.Programming:AL5SpsOfflinePhase.CompletedObservations;}
                return AL5SpsSavedFrameDisposition.Advanced;
            }
            try
            {
                if(transmitted)program.ObserveRequest(m);else program.ObserveReply(m);
            }
            catch(ArgumentException){return Reject("Saved programming frame does not match its pending owner.");}
            catch(InvalidOperationException){return Reject("Saved programming frame arrived without an available owner.");}
            if(program.State==AL5SpsOfflineState.Stopped)return Reject(program.StopReason);
            if(program.State==AL5SpsOfflineState.CompletedObservations){Phase=AL5SpsOfflinePhase.Cleanup;return AL5SpsSavedFrameDisposition.Advanced;}
            return program.State==AL5SpsOfflineState.BlockReply || program.State==AL5SpsOfflineState.LoaderReply
                ?AL5SpsSavedFrameDisposition.Pending:AL5SpsSavedFrameDisposition.Advanced;
        }
        public void Interrupt()
        {
            if(Phase==AL5SpsOfflinePhase.CompletedObservations || Phase==AL5SpsOfflinePhase.Stopped)throw new InvalidOperationException("Saved lifecycle is closed.");
            Reject("Saved interruption; physical outcome and recovery remain unknown.");
        }
    }
}

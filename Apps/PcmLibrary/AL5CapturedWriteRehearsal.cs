// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Security.Cryptography;

namespace PcmHacking
{
    public enum AL5CapturedWriteState
    {
        BootRequest, BootReply, LoaderTransfer, LoaderIdentityRequest, LoaderIdentityReply,
        EraseRequest, EraseReply, Programming, FinalizeRequest, FinalizeReply,
        AwaitingSavedVerification, SavedImageVerified, Stopped
    }

    /// <summary>Offline, ordered replay of selected saved frames. Never a live protocol executor.</summary>
    public sealed class AL5CapturedWriteRehearsal
    {
        private readonly byte[] candidate;
        private readonly string loaderSha256;
        private readonly AL5CapturedProgramSession program = new AL5CapturedProgramSession();
        private int bootReplies;
        public AL5CapturedWriteState State { get; private set; } = AL5CapturedWriteState.BootRequest;
        public bool? SavedCalibrationMatches { get; private set; }
        public int PositiveProgramReplies => program.PositiveReplies;
        public int ChecksumErrors => program.ChecksumErrors;
        public bool LiveWriteEnabled => false;
        public bool ReadyToFlash => false;
        public bool RecoveryVerified => false;
        public bool PhysicalReadbackVerified => false;
        public bool SecurityAuthorizationProven => false;

        public AL5CapturedWriteRehearsal(byte[] calibration, string expectedLoaderSha256)
        {
            if(calibration==null) throw new ArgumentNullException(nameof(calibration));
            if(calibration.Length!=AL5CalibrationInspection.Length) throw new ArgumentException("Exact calibration required.");
            candidate=(byte[])calibration.Clone();
            if(!AL5CalibrationInspection.Inspect(candidate).ChecksPass) throw new ArgumentException("Invalid calibration.");
            if(expectedLoaderSha256==null || expectedLoaderSha256.Length!=64) throw new ArgumentException("Pinned loader hash required.");
            foreach(char c in expectedLoaderSha256)
                if(!Uri.IsHexDigit(c)) throw new ArgumentException("Invalid loader hash.");
            loaderSha256=expectedLoaderSha256.ToLowerInvariant();
        }

        private static bool Is(byte[] value, params byte[] expected)
        {
            if(value.Length!=expected.Length)return false;
            for(int i=0;i<value.Length;i++)if(value[i]!=expected[i])return false;
            return true;
        }

        public void Observe(bool transmitted, byte[] message)
        {
            if(message==null)throw new ArgumentNullException(nameof(message));
            if(message.Length>1602)throw new ArgumentException("Outside captured message profile.");
            var m=(byte[])message.Clone();
            if(State==AL5CapturedWriteState.Stopped || State==AL5CapturedWriteState.SavedImageVerified || State==AL5CapturedWriteState.AwaitingSavedVerification)
                throw new InvalidOperationException("No pending wire observation.");
            if(!transmitted && m.Length>=4 && m[1]==0xF0 && m[2]==0x18 &&
               (m[0]==0x6C || m[0]==0x6D) && m[3]==0x7F)
            {State=AL5CapturedWriteState.Stopped;return;}
            if(!transmitted && (State==AL5CapturedWriteState.EraseReply || State==AL5CapturedWriteState.FinalizeReply) &&
               m.Length==6 && m[0]==0x6C && m[1]==0xF0 && m[2]==0x18 && m[3]==0x76 && m[4]==0 &&
               (m[5]==0x77 || m[5]==0x85 || m[5]==0x89 || m[5]==0xF8 || m[5]==0xFF))
            {State=AL5CapturedWriteState.Stopped;return;}
            bool accepted=false;
            switch(State)
            {
                case AL5CapturedWriteState.BootRequest:
                    if(transmitted && Is(m,0x6C,0x18,0xF0,0x34)){State=AL5CapturedWriteState.BootReply;accepted=true;}break;
                case AL5CapturedWriteState.BootReply:
                    if(!transmitted && Is(m,0x6C,0xF0,0x18,0x74,0x44))
                    {bootReplies++;State=bootReplies==2?AL5CapturedWriteState.LoaderTransfer:AL5CapturedWriteState.BootRequest;accepted=true;}break;
                case AL5CapturedWriteState.LoaderTransfer:
                    if(transmitted && m.Length==1602 && m[0]==0x6D && m[1]==0x18 && m[2]==0xF0 && m[3]==0x36 && m[4]==0x80 &&
                       m[5]==6 && m[6]==0x36 && m[7]==0xFF && m[8]==0x90 && m[9]==0)
                    {
                        int sum=0;for(int i=4;i<m.Length-2;i++)sum=(sum+m[i])&65535;
                        using(var sha=SHA256.Create())
                        {
                            string hash=BitConverter.ToString(sha.ComputeHash(m,10,1590)).Replace("-","").ToLowerInvariant();
                            if(hash==loaderSha256 && sum==((m[1600]<<8)|m[1601]))
                            {State=AL5CapturedWriteState.LoaderIdentityRequest;accepted=true;}
                        }
                    }break;
                case AL5CapturedWriteState.LoaderIdentityRequest:
                    if(transmitted && Is(m,0x6C,0x18,0xF0,0x3C,0x0A)){State=AL5CapturedWriteState.LoaderIdentityReply;accepted=true;}break;
                case AL5CapturedWriteState.LoaderIdentityReply:
                    if(!transmitted && Is(m,0x6C,0xF0,0x18,0x7C,0x0A,0,0xE7,0xB0,0xED)){State=AL5CapturedWriteState.EraseRequest;accepted=true;}break;
                case AL5CapturedWriteState.EraseRequest:
                    if(transmitted && Is(m,0x6C,0x18,0xF0,0x36,0xEE)){State=AL5CapturedWriteState.EraseReply;accepted=true;}break;
                case AL5CapturedWriteState.EraseReply:
                    if(!transmitted && Is(m,0x6C,0xF0,0x18,0x76,0,0xEE)){State=AL5CapturedWriteState.Programming;accepted=true;}break;
                case AL5CapturedWriteState.Programming:
                    if(transmitted)program.ObserveRequest(m);
                    else
                    {
                        if(m.Length!=6 || m[0]!=0x6D || m[1]!=0xF0 || m[2]!=0x18)break;
                        program.ObserveReply(new[]{m[3],m[4],m[5]});
                    }
                    accepted=true;
                    if(program.State==AL5CapturedProgramState.Stopped)State=AL5CapturedWriteState.Stopped;
                    else if(program.State==AL5CapturedProgramState.BlocksAcknowledged)
                    {
                        byte[] image=program.CopyAcknowledgedCapture();
                        for(int i=0;i<candidate.Length;i++)if(image[i]!=candidate[i]){State=AL5CapturedWriteState.Stopped;return;}
                        State=AL5CapturedWriteState.FinalizeRequest;
                    }break;
                case AL5CapturedWriteState.FinalizeRequest:
                    if(transmitted && Is(m,0x6C,0x18,0xF0,0x36,0xFF)){State=AL5CapturedWriteState.FinalizeReply;accepted=true;}break;
                case AL5CapturedWriteState.FinalizeReply:
                    if(!transmitted && Is(m,0x6C,0xF0,0x18,0x76,0,0x86)){State=AL5CapturedWriteState.AwaitingSavedVerification;accepted=true;}break;
            }
            if(!accepted)throw new ArgumentException("Unexpected, malformed or out-of-order captured frame; state retained.");
        }

        public void Interrupt() { if(State!=AL5CapturedWriteState.SavedImageVerified)State=AL5CapturedWriteState.Stopped; }

        public void CompareSavedCalibration(byte[] readback)
        {
            if(State!=AL5CapturedWriteState.AwaitingSavedVerification)throw new InvalidOperationException("Finalization not observed.");
            if(readback==null || readback.Length!=candidate.Length)throw new ArgumentException("Exact saved calibration required.");
            bool equal=true;for(int i=0;i<candidate.Length;i++)if(candidate[i]!=readback[i])equal=false;
            SavedCalibrationMatches=equal;
            if(!equal)State=AL5CapturedWriteState.Stopped;
            // Calibration alone excludes collateral and marker. Never complete the rehearsal here.
        }

        public AL5ProgrammingAssessment VerifySavedSnapshot(byte[] snapshot, byte[] independentCollateral)
        {
            if(State!=AL5CapturedWriteState.AwaitingSavedVerification)throw new InvalidOperationException("Finalization not observed.");
            if(snapshot==null || independentCollateral==null)throw new ArgumentNullException();
            program.AssessReference(candidate,independentCollateral);
            var assessment=AL5ProgrammingWorkflow.Assess(candidate,snapshot,independentCollateral);
            State=assessment.ExactSavedImageMatch?AL5CapturedWriteState.SavedImageVerified:AL5CapturedWriteState.Stopped;
            return assessment;
        }
    }
}

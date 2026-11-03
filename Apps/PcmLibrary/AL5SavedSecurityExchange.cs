// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    public enum AL5SavedSecurityState { AwaitingSeedRequest, AwaitingSeedReply, KeyReviewRequired, KeyReviewed, AwaitingKeyReply, Accepted, Stopped }
    public enum AL5SavedSecurityFailure { None, UnsupportedSeed, ShortSeedReply, Malformed, InvalidSequence, InvalidKey, AttemptsExceeded, DelayRequired, NegativeResponse, Interrupted }

    /// <summary>One saved selector-zero exchange bound to a fingerprinted original image. No sender or generic key algorithm.</summary>
    public sealed class AL5SavedSecurityExchange
    {
        private readonly ushort expectedSeed,expectedKey;
        public AL5SavedSecurityExchange(byte[] original)
        {
            if(original==null || original.Length!=0x100000)throw new ArgumentException("Complete saved original required.");
            var owned=(byte[])original.Clone();var cal=new byte[AL5CalibrationInspection.Length];
            Buffer.BlockCopy(owned,0x8000,cal,0,cal.Length);
            if(!AL5CalibrationWriteProfile.InspectSavedReference(owned,cal).SavedBytesMatchProfile)
                throw new ArgumentException("Security requires the fingerprinted selector-zero boot and OS profile.");
            expectedSeed=(ushort)((owned[0x3FD8]<<8)|owned[0x3FD9]);
            expectedKey=(ushort)((owned[0x3FDA]<<8)|owned[0x3FDB]);
        }
        public AL5SavedSecurityState State { get; private set; }
        public AL5SavedSecurityFailure Failure { get; private set; }
        public ushort? ObservedSeed { get; private set; }
        public byte? ObservedStatus { get; private set; }
        public bool SavedAcceptanceObserved=>State==AL5SavedSecurityState.Accepted;
        public bool FreshPhysicalSecurityVerified=>false;
        public bool LiveSecuritySubmissionEnabled=>false;
        public bool GeneralFreshSeedSupportVerified=>false;

        private void Stop(AL5SavedSecurityFailure failure){Failure=failure;State=AL5SavedSecurityState.Stopped;}
        private void Require(AL5SavedSecurityState state)
        {
            if(State==state)return;
            if(State!=AL5SavedSecurityState.Accepted && State!=AL5SavedSecurityState.Stopped)Stop(AL5SavedSecurityFailure.InvalidSequence);
            throw new InvalidOperationException("No security slot owns this observation.");
        }
        private static bool Exact(byte[] bytes,params byte[] expected)
        {
            if(bytes==null || bytes.Length!=expected.Length)return false;
            for(int i=0;i<bytes.Length;i++)if(bytes[i]!=expected[i])return false;return true;
        }
        public void ObserveSavedSeedRequestAccepted(byte[] request)
        {
            Require(AL5SavedSecurityState.AwaitingSeedRequest);
            if(!Exact(request,0x6C,0x18,0xF0,0x27,1)){Stop(AL5SavedSecurityFailure.Malformed);return;}
            State=AL5SavedSecurityState.AwaitingSeedReply;
        }
        public void ObserveSavedSeedReply(byte[] reply)
        {
            Require(AL5SavedSecurityState.AwaitingSeedReply);
            if(Negative(reply))return;
            var seed=AL5SavedSecuritySeed.Parse(reply);ObservedSeed=seed.Seed;
            if(seed.Kind==AL5SavedSeedKind.Short37Unqualified){Stop(AL5SavedSecurityFailure.ShortSeedReply);return;}
            if(seed.Kind!=AL5SavedSeedKind.Seed){Stop(AL5SavedSecurityFailure.Malformed);return;}
            // Zero may mean already unlocked in native synthetic state, but that branch
            // is not the captured writer lifecycle and must not silently bypass review.
            if(seed.Seed!=expectedSeed){Stop(AL5SavedSecurityFailure.UnsupportedSeed);return;}
            State=AL5SavedSecurityState.KeyReviewRequired;
        }
        public void ReviewSavedKeyRequest(byte[] request)
        {
            Require(AL5SavedSecurityState.KeyReviewRequired);
            if(!Exact(request,0x6C,0x18,0xF0,0x27,2,(byte)(expectedKey>>8),(byte)expectedKey))
            {Stop(AL5SavedSecurityFailure.InvalidKey);return;}
            State=AL5SavedSecurityState.KeyReviewed;
        }
        public void ObserveSavedKeyRequestAccepted(byte[] request)
        {
            Require(AL5SavedSecurityState.KeyReviewed);
            if(!Exact(request,0x6C,0x18,0xF0,0x27,2,(byte)(expectedKey>>8),(byte)expectedKey))
            {Stop(AL5SavedSecurityFailure.InvalidKey);return;}
            State=AL5SavedSecurityState.AwaitingKeyReply;
        }
        public void ObserveSavedKeyReply(byte[] reply)
        {
            Require(AL5SavedSecurityState.AwaitingKeyReply);
            if(Negative(reply))return;
            if(reply==null || reply.Length!=6 || reply[0]!=0x6C || reply[1]!=0xF0 || reply[2]!=0x18 || reply[3]!=0x67 || reply[4]!=2)
            {Stop(AL5SavedSecurityFailure.Malformed);return;}
            ObservedStatus=reply[5];
            switch(reply[5])
            {
                case 0x34:State=AL5SavedSecurityState.Accepted;break;
                case 0x35:Stop(AL5SavedSecurityFailure.InvalidKey);break;
                case 0x36:Stop(AL5SavedSecurityFailure.AttemptsExceeded);break;
                case 0x37:Stop(AL5SavedSecurityFailure.DelayRequired);break;
                default:Stop(AL5SavedSecurityFailure.Malformed);break;
            }
        }
        private bool Negative(byte[] reply)
        {
            if(reply!=null && reply.Length==6 && reply[0]==0x6C && reply[1]==0xF0 && reply[2]==0x18 && reply[3]==0x7F && reply[4]==0x27)
            {ObservedStatus=reply[5];Stop(AL5SavedSecurityFailure.NegativeResponse);return true;}return false;
        }
        public void Interrupt()
        {
            if(State!=AL5SavedSecurityState.Accepted && State!=AL5SavedSecurityState.Stopped)Stop(AL5SavedSecurityFailure.Interrupted);
        }
    }
}

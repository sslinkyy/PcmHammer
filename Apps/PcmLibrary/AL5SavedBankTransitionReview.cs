// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace PcmHacking
{
    /// <summary>One caller-supplied, atomic saved-model program. Never a flash command.</summary>
    public sealed class AL5SavedBankProgram
    {
        private readonly byte[] before,after;
        public AL5SavedBankProgram(int callerReturn,int address,byte[] before,byte[] after)
        {
            if(before==null || after==null)throw new ArgumentNullException();
            if(before.Length!=after.Length || (before.Length!=2 && before.Length!=10))throw new ArgumentException("Saved small-record program requires two or ten bytes.");
            CallerReturn=callerReturn;Address=address;this.before=(byte[])before.Clone();this.after=(byte[])after.Clone();
        }
        public int CallerReturn { get; }
        public int Address { get; }
        public byte[] CopyBefore()=>(byte[])before.Clone();
        public byte[] CopyAfter()=>(byte[])after.Clone();
    }

    public sealed class AL5SavedBankTransitionAssessment
    {
        private readonly int[] changed,mismatched;
        internal AL5SavedBankTransitionAssessment(int[] changed,int[] mismatched)
        {this.changed=changed;this.mismatched=mismatched;}
        public int ChangedFromPreparedBytes=>changed.Length;
        public int DifferencesFromPrediction=>mismatched.Length;
        public bool MatchesSavedPrediction=>mismatched.Length==0;
        public int[] CopyChangedAddresses()=>(int[])changed.Clone();
        public int[] CopyPredictionMismatchAddresses()=>(int[])mismatched.Clone();
        public bool PhysicalTransitionVerified=>false;
        public bool PreservationVerified=>false;
        public bool LiveWriteEnabled=>false;
        public bool ReadyToFlash=>false;
    }

    /// <summary>
    /// Strict diagnostic replay of the saved profile's small-record programs.
    /// Explains an exact model outcome without accepting it as physical preservation.
    /// </summary>
    public sealed class AL5SavedBankTransitionReview
    {
        private readonly byte[] prepared,predicted;
        public AL5SavedBankTransitionReview(string evidenceId,string originalSha256,byte[] preparedBanks,AL5SavedBankProgram[] operations)
        {
            if(string.IsNullOrWhiteSpace(evidenceId))throw new ArgumentException("Explicit saved prediction identity required.");
            if(originalSha256==null || originalSha256.Length!=64)throw new ArgumentException("Complete original-image SHA256 required.");
            foreach(char value in originalSha256)if(!((value>='0'&&value<='9')||(value>='a'&&value<='f')))throw new ArgumentException("Canonical SHA256 required.");
            if(preparedBanks==null || preparedBanks.Length!=AL5PreparedBankReference.Length)throw new ArgumentException("Complete explicit prepared banks required.");
            if(operations==null)throw new ArgumentNullException(nameof(operations));
            EvidenceId=evidenceId;OriginalSha256=originalSha256;prepared=(byte[])preparedBanks.Clone();predicted=(byte[])prepared.Clone();
            foreach(var operation in operations)
            {
                if(operation==null)throw new ArgumentException("Missing saved operation.");
                byte[] before=operation.CopyBefore(),after=operation.CopyAfter();
                int relative=operation.Address-AL5PreparedBankReference.StartAddress;
                int slotOffset=-1;
                foreach(int bank in new[]{0x4000,0x6000})
                    for(int slot=0;slot<4;slot++)
                        if(operation.Address==bank+0xA1C+slot*12 || operation.Address==bank+0xA1E+slot*12)
                            slotOffset=operation.Address-(bank+0xA1C+slot*12);
                bool first=operation.CallerReturn==0x229C2 && slotOffset==0 && after.Length==2 && after[0]==0xFF && after[1]==0xFE;
                bool payload=operation.CallerReturn==0x229DC && slotOffset==2 && after.Length==10;
                bool commit=operation.CallerReturn==0x229F6 && slotOffset==0 && after.Length==2 && after[0]==0xFF && after[1]==0xAA;
                if(!(first||payload||commit) || relative<0 || relative>predicted.Length-before.Length)
                    throw new ArgumentException("Operation is outside the traced small-record caller/layout.");
                for(int i=0;i<before.Length;i++)
                    if(predicted[relative+i]!=before[i] || (before[i]&after[i])!=after[i])
                        throw new ArgumentException("Saved operation does not own its before bytes or requires an unmodeled erase.");
                Buffer.BlockCopy(after,0,predicted,relative,after.Length);OperationCount++;
            }
            PreparedBanksSha256=Hash(prepared);PredictedBanksSha256=Hash(predicted);
        }
        private static string Hash(byte[] bytes)
        {using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();}
        public string EvidenceId { get; }
        public string OriginalSha256 { get; }
        public string PreparedBanksSha256 { get; }
        public string PredictedBanksSha256 { get; }
        public int OperationCount { get; }
        public bool PhysicalTransitionVerified=>false;
        public bool LiveWriteEnabled=>false;
        public byte[] CopyPredictedBanks()=>(byte[])predicted.Clone();
        public AL5SavedBankTransitionAssessment CompareSavedBanks(byte[] observedBanks)
        {
            if(observedBanks==null || observedBanks.Length!=prepared.Length)throw new ArgumentException("All saved bank bytes required.");
            observedBanks=(byte[])observedBanks.Clone();
            var changed=new List<int>();var mismatched=new List<int>();
            for(int i=0;i<prepared.Length;i++)
            {
                if(observedBanks[i]!=prepared[i])changed.Add(AL5PreparedBankReference.StartAddress+i);
                if(observedBanks[i]!=predicted[i])mismatched.Add(AL5PreparedBankReference.StartAddress+i);
            }
            return new AL5SavedBankTransitionAssessment(changed.ToArray(),mismatched.ToArray());
        }
    }
}

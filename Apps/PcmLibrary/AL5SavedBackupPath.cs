// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Security.Cryptography;

namespace PcmHacking
{
    public enum AL5SavedBackupPhase { OriginalAcquisition, EntryBoundaryRecorded, PreparedAcquisition, Complete, Stopped }

    /// <summary>Ordered saved-response acquisition of original flash and prepared banks. Not proof of physical acquisition or safe reader entry.</summary>
    public sealed class AL5SavedBackupPath
    {
        private readonly AL5ReadOnlyFlashCampaign original;
        private readonly AL5ReadOnlyRangeCampaign prepared;
        private AL5PreparedBankReference? reference;
        private byte[]? originalImage;
        public AL5SavedBackupPath(string evidenceId,byte[] originalNonce,byte[] preparedNonce)
        {
            if(string.IsNullOrWhiteSpace(evidenceId))throw new ArgumentException("Explicit saved evidence identity required.");
            // Constructors validate and clone each nonce before any session is used.
            original=new AL5ReadOnlyFlashCampaign(originalNonce);
            prepared=new AL5ReadOnlyRangeCampaign(new AL5ReadOnlyCoreSession(preparedNonce),AL5PreparedBankReference.StartAddress,AL5PreparedBankReference.Length);
            bool same=true;for(int i=0;i<8;i++)same&=originalNonce[i]==preparedNonce[i];
            if(same)throw new ArgumentException("Original and prepared acquisition require distinct nonces.");
            EvidenceId=evidenceId;
        }
        public string EvidenceId { get; }
        public AL5SavedBackupPhase Phase { get; private set; }
        public int OriginalBytesObserved=>original.BytesObserved;
        public int PreparedBytesObserved=>prepared.BytesObserved;
        public string? OriginalSha256 { get; private set; }
        public string? PreparedBanksSha256=>reference?.PreparedSha256;
        public int? SavedPreparationChangedBytes=>reference?.ChangedBytes;
        public bool PreEntryPhysicalAcquisitionVerified=>false;
        public bool PhysicalAddressMappingVerified=>false;
        public bool LiveUploadEnabled=>false;
        public bool LiveExecutionEnabled=>false;
        public bool LiveWriteEnabled=>false;
        public bool ReadyToFlash=>false;
        public byte[] BeginNextSavedRequest()
        {
            if(Phase==AL5SavedBackupPhase.OriginalAcquisition)return original.BeginNextSavedVpwRequest();
            if(Phase==AL5SavedBackupPhase.EntryBoundaryRecorded)Phase=AL5SavedBackupPhase.PreparedAcquisition;
            if(Phase==AL5SavedBackupPhase.PreparedAcquisition)return prepared.BeginNextSavedVpwRequest();
            throw new InvalidOperationException("No acquisition slot available.");
        }
        public AL5ReadOnlyCoreReply ObserveSavedReply(byte[] reply)
        {
            AL5ReadOnlyCoreReply result;
            if(Phase==AL5SavedBackupPhase.OriginalAcquisition)
            {
                result=original.ObserveSavedVpwReply(reply);
                if(original.Stopped)Phase=AL5SavedBackupPhase.Stopped;
                if(original.Complete && originalImage==null)
                {
                    originalImage=original.CopySavedImage();
                    using(var hash=SHA256.Create())OriginalSha256=BitConverter.ToString(hash.ComputeHash(originalImage)).Replace("-","").ToLowerInvariant();
                }
            }
            else if(Phase==AL5SavedBackupPhase.PreparedAcquisition)
            {
                result=prepared.ObserveSavedVpwReply(reply);
                if(prepared.Stopped)Phase=AL5SavedBackupPhase.Stopped;
                if(prepared.Complete)
                {
                    var banks=new byte[AL5PreparedBankReference.Length];Buffer.BlockCopy(originalImage!,AL5PreparedBankReference.StartAddress,banks,0,banks.Length);
                    reference=new AL5PreparedBankReference(banks,prepared.CopySavedBytes());Phase=AL5SavedBackupPhase.Complete;
                }
            }
            else throw new InvalidOperationException("No pending acquisition owns this reply.");
            return result;
        }
        public void RecordEntryBoundaryForOfflineReview()
        {
            if(Phase!=AL5SavedBackupPhase.OriginalAcquisition || !original.Complete)
                throw new InvalidOperationException("Complete original coverage is required before recording entry.");
            Phase=AL5SavedBackupPhase.EntryBoundaryRecorded;
        }
        public byte[] CopyOriginalImage()
        {
            if(originalImage==null)throw new InvalidOperationException("Original image is incomplete; unknown bytes cannot be filled.");
            return (byte[])originalImage.Clone();
        }
        public AL5PreparedBankReference CopyPreparedReference()
        {
            if(reference==null || Phase!=AL5SavedBackupPhase.Complete)throw new InvalidOperationException("Both saved acquisition epochs must be complete.");
            return new AL5PreparedBankReference(reference.CopyOriginal(),reference.CopyPrepared());
        }
        public void TimeoutOrCancel()
        {
            if(Phase==AL5SavedBackupPhase.Complete || Phase==AL5SavedBackupPhase.Stopped)throw new InvalidOperationException("Backup path is terminal.");
            if(Phase==AL5SavedBackupPhase.OriginalAcquisition && !original.Complete)original.TimeoutOrCancel();
            if(Phase==AL5SavedBackupPhase.PreparedAcquisition)prepared.TimeoutOrCancel();
            Phase=AL5SavedBackupPhase.Stopped;
        }
    }
}

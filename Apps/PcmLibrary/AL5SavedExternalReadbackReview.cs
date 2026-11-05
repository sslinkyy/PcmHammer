// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Security.Cryptography;

namespace PcmHacking
{
    public enum AL5SavedExternalReadbackEpoch { ShutdownDeclared, PowerHistoryUnobserved }
    /// <summary>External saved-pair comparison. No experimental reader, upload, hardware or live authority.</summary>
    public sealed class AL5SavedExternalReadbackReview
    {
        public AL5SavedExternalReadbackReview(byte[] loader,byte[] original,byte[] prepared,
            (bool Transmitted,byte[] Frame)[] frames,AL5SavedExternalFlashPair readback,
            string targetId,string evidenceId,AL5SavedExternalReadbackEpoch epoch)
        {
            if(readback==null)throw new ArgumentNullException(nameof(readback));
            if(string.IsNullOrWhiteSpace(targetId) || string.IsNullOrWhiteSpace(evidenceId))throw new ArgumentException("Explicit target and readback evidence identities required.");
            if(!Enum.IsDefined(typeof(AL5SavedExternalReadbackEpoch),epoch))throw new ArgumentOutOfRangeException(nameof(epoch));
            var candidate=AL5SavedReadbackEpoch.RehearseSavedCandidate(loader,original,prepared,frames);
            TargetId=targetId;EvidenceId=evidenceId;Epoch=epoch;OriginalSha256=candidate.BaselineSha256;
            PreparedBanksSha256=candidate.PreparedBanksSha256!;ExpectedImageSha256=Hash(candidate.CopyExpectedSavedImage());
            ObservedImageSha256=readback.CanonicalSha256;ReadbackAllFF=readback.AllFF;ReadbackAllZero=readback.AllZero;
            // A blank or corrupted post-write chip image is useful failure evidence.
            // It must fail the comparator rather than be rejected as an invalid original.
            candidate.VerifySavedFullReadback(readback.CopyCanonical());
            StrictSavedComparisonMatched=candidate.CompleteSavedComparison;
            ChangedPersistentBankBytes=candidate.ChangedPersistentBankBytes;ChangedOtherProtectedBytes=candidate.ChangedOtherProtectedBytes;
        }
        private static string Hash(byte[] b){using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(b)).Replace("-","").ToLowerInvariant();}
        public string TargetId { get; }
        public string EvidenceId { get; }
        public AL5SavedExternalReadbackEpoch Epoch { get; }
        public string OriginalSha256 { get; }
        public string PreparedBanksSha256 { get; }
        public string ExpectedImageSha256 { get; }
        public string ObservedImageSha256 { get; }
        public bool StrictSavedComparisonMatched { get; }
        public int? ChangedPersistentBankBytes { get; }
        public int? ChangedOtherProtectedBytes { get; }
        public bool ReadbackAllFF { get; }
        public bool ReadbackAllZero { get; }
        public string AcquisitionKind=>"external_saved_flash_pair";
        public bool ExperimentalReaderUploadRequired=>false;
        public bool OperatorTargetContinuityVerified=>false;
        public bool IndependentPhysicalReadsVerified=>false;
        public bool PhysicalPowerStateVerified=>false;
        public bool SnapshotCoherenceVerified=>false;
        public bool PhysicalReadbackVerified=>false;
        public bool PreservationVerified=>false;
        public bool RecoveryVerified=>false;
        public bool LiveUploadEnabled=>false;
        public bool LiveExecutionEnabled=>false;
        public bool LiveWriteEnabled=>false;
        public bool ReadyToFlash=>false;
    }
}

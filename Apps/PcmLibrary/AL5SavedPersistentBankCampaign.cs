// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    /// <summary>
    /// Offline resident Mode 23 bank acquisition rehearsal. This owns one saved
    /// interval, not a physical session boundary or proof that entry has not run.
    /// </summary>
    public sealed class AL5SavedPersistentBankCampaign
    {
        public const int StartAddress = 0x4000;
        public const int Length = 0x4000;
        private readonly AL5SpsSavedReadCampaign correlation;
        private readonly byte[] bytes = new byte[Length];

        public AL5SavedPersistentBankCampaign(byte[] pinnedSpsOs)
        {
            correlation = new AL5SpsSavedReadCampaign(pinnedSpsOs);
        }

        public int BytesObserved { get; private set; }
        public int UnknownByteCount => Length - BytesObserved;
        public bool Complete => BytesObserved == Length;
        public bool Stopped => correlation.Stopped;
        public bool HasPendingRequest => correlation.HasPendingRequest;
        public bool PreEntryAcquisitionProven => false;
        public bool FreshnessProven => false;
        public bool FullAddressIdentityProven => false;
        public bool LiveReadEnabled => false;
        public bool LiveUploadEnabled => false;
        public bool LiveExecutionEnabled => false;
        public bool LiveWriteEnabled => false;
        public bool ReadyToFlash => false;

        // Returns bytes for saved-transcript comparison only. No transport owns this class.
        public byte[] BeginNextSavedVpwRequest()
        {
            RequireOpen();
            int address = StartAddress + BytesObserved;
            correlation.BeginSavedRequest(address);
            return new byte[] { 0x6D, 0x18, 0xF0, 0x23,
                (byte)(address >> 16), (byte)(address >> 8), (byte)address, 1 };
        }

        public AL5SavedReplyKind ObserveSavedVpwReply(byte[] message, out byte? negativeReason)
        {
            RequireOpen();
            var kind = correlation.ObserveSavedReply(message, out byte[] data, out negativeReason);
            if (kind == AL5SavedReplyKind.MatchingLow16Echo)
            {
                Buffer.BlockCopy(data, 0, bytes, BytesObserved, data.Length);
                BytesObserved += data.Length;
            }
            return kind;
        }

        public void TimeoutOrCancel()
        {
            RequireOpen();
            correlation.TimeoutOrCancel();
        }

        public byte[] CopyCompleteSavedBanks()
        {
            if (!Complete) throw new InvalidOperationException("Missing bank bytes cannot be synthesized.");
            return (byte[])bytes.Clone();
        }

        private void RequireOpen()
        {
            if (Complete || Stopped) throw new InvalidOperationException("Saved bank campaign is terminal.");
        }
    }
}

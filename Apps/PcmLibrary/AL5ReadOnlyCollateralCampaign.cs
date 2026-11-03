// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    /// <summary>Offline correlated reader campaign, not an adapter/upload/execution backend.</summary>
    public sealed class AL5ReadOnlyCollateralCampaign
    {
        private readonly AL5ReadOnlyRangeCampaign campaign;
        public int BytesObserved => campaign.BytesObserved;
        public int MatchedReplies => campaign.MatchedReplies;
        public bool Complete => campaign.Complete;
        public bool Stopped => campaign.Stopped;
        public bool HasPendingRequest => campaign.HasPendingRequest;
        public bool LiveUploadEnabled => false;
        public bool LiveExecutionEnabled => false;
        public bool LiveWriteEnabled => false;
        public bool HardwareQualified => false;
        public bool PhysicalReadbackVerified => false;
        public bool IndependentCollateralBackupVerified => false;
        public ushort? SavedCompletionMarker
        {
            get { if(!Complete)return null;var bytes=campaign.CopySavedRange(AL5SavedReadCoverage.SupplementLength-2,2);return (ushort)((bytes[0]<<8)|bytes[1]); }
        }

        public AL5ReadOnlyCollateralCampaign(byte[] nonce):this(new AL5ReadOnlyCoreSession(nonce)){}
        private AL5ReadOnlyCollateralCampaign(AL5ReadOnlyCoreSession session){campaign=new AL5ReadOnlyRangeCampaign(session,AL5SavedReadCoverage.SupplementStart,AL5SavedReadCoverage.SupplementLength);}
        public static AL5ReadOnlyCollateralCampaign CreateOffline()=>new AL5ReadOnlyCollateralCampaign(AL5ReadOnlyCoreSession.CreateOffline());
        public byte[] BeginNextSavedVpwRequest()=>campaign.BeginNextSavedVpwRequest();
        public AL5ReadOnlyCoreReply ObserveSavedVpwReply(byte[] frame)=>campaign.ObserveSavedVpwReply(frame);
        public void TimeoutOrCancel()=>campaign.TimeoutOrCancel();
        public byte[] CopySavedSupplement()=>campaign.CopySavedBytes();
        public byte[] CopySavedCollateral()
        {
            if(!Complete)throw new InvalidOperationException("Complete correlated supplement required.");
            return campaign.CopySavedRange(0,AL5ProgrammingWorkflow.CollateralLength);
        }
        public byte[] AssembleSavedSnapshot(byte[] calibration)=>AL5SavedReadCoverage.AssembleSavedSnapshot(calibration,CopySavedSupplement());
    }
}

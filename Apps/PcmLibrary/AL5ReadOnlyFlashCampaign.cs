// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    /// <summary>Full 1 MiB saved-response campaign only; no adapter, upload or execution backend.</summary>
    public sealed class AL5ReadOnlyFlashCampaign
    {
        public const int ImageLength=0x100000;
        private readonly AL5ReadOnlyRangeCampaign campaign;
        public AL5ReadOnlyFlashCampaign(byte[] nonce):this(new AL5ReadOnlyCoreSession(nonce)){}
        private AL5ReadOnlyFlashCampaign(AL5ReadOnlyCoreSession session)
        {campaign=new AL5ReadOnlyRangeCampaign(session,0,ImageLength);}
        public static AL5ReadOnlyFlashCampaign CreateOffline()=>new AL5ReadOnlyFlashCampaign(AL5ReadOnlyCoreSession.CreateOffline());
        public int BytesObserved=>campaign.BytesObserved;
        public int UnknownByteCount=>ImageLength-BytesObserved;
        public int MatchedReplies=>campaign.MatchedReplies;
        public bool Complete=>campaign.Complete;
        public bool Stopped=>campaign.Stopped;
        public bool HasPendingRequest=>campaign.HasPendingRequest;
        public bool LiveUploadEnabled=>false;
        public bool LiveExecutionEnabled=>false;
        public bool LiveWriteEnabled=>false;
        public bool PhysicalReadbackVerified=>false;
        public bool PhysicalAddressMappingVerified=>false;
        public bool RecoveryVerified=>false;
        public bool ReadyToFlash=>false;
        public byte[] BeginNextSavedVpwRequest()=>campaign.BeginNextSavedVpwRequest();
        public AL5ReadOnlyCoreReply ObserveSavedVpwReply(byte[] frame)=>campaign.ObserveSavedVpwReply(frame);
        public void TimeoutOrCancel()=>campaign.TimeoutOrCancel();
        public byte[] CopySavedImage()=>campaign.CopySavedBytes();
    }
}

// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    /// <summary>Offline correlated reader campaign, not an adapter/upload/execution backend.</summary>
    public sealed class AL5ReadOnlyCollateralCampaign
    {
        private readonly AL5ReadOnlyCoreSession session;
        private readonly byte[] supplement=new byte[AL5SavedReadCoverage.SupplementLength];
        public int BytesObserved { get; private set; }
        public int MatchedReplies { get; private set; }
        public bool Complete => BytesObserved==supplement.Length && !Stopped;
        public bool Stopped => session.Stopped;
        public bool HasPendingRequest => session.HasPendingRequest;
        public bool LiveUploadEnabled => false;
        public bool LiveExecutionEnabled => false;
        public bool LiveWriteEnabled => false;
        public bool HardwareQualified => false;
        public bool PhysicalReadbackVerified => false;
        public bool IndependentCollateralBackupVerified => false;
        public ushort? SavedCompletionMarker => Complete?(ushort?)((supplement[supplement.Length-2]<<8)|supplement[supplement.Length-1]):null;

        public AL5ReadOnlyCollateralCampaign(byte[] nonce):this(new AL5ReadOnlyCoreSession(nonce)){}
        private AL5ReadOnlyCollateralCampaign(AL5ReadOnlyCoreSession session){this.session=session;}
        public static AL5ReadOnlyCollateralCampaign CreateOffline()=>new AL5ReadOnlyCollateralCampaign(AL5ReadOnlyCoreSession.CreateOffline());
        public byte[] BeginNextSavedVpwRequest()
        {
            if(Complete || Stopped)throw new InvalidOperationException("Offline campaign is closed.");
            return session.BeginSavedVpwRead((uint)(AL5SavedReadCoverage.SupplementStart+BytesObserved),Math.Min(32,supplement.Length-BytesObserved));
        }
        public AL5ReadOnlyCoreReply ObserveSavedVpwReply(byte[] frame)
        {
            var result=session.ObserveSavedVpwReply(frame,out var bytes);
            if(result==AL5ReadOnlyCoreReply.Matched)
            {
                Array.Copy(bytes,0,supplement,BytesObserved,bytes.Length);
                BytesObserved+=bytes.Length;MatchedReplies++;
            }
            return result;
        }
        public void TimeoutOrCancel()
        {
            if(Complete || Stopped)throw new InvalidOperationException("Offline campaign is closed.");
            session.TimeoutOrCancel();
        }
        public byte[] CopySavedSupplement()
        {
            if(!Complete)throw new InvalidOperationException("Complete correlated supplement required; missing bytes cannot be invented.");
            return (byte[])supplement.Clone();
        }
        public byte[] CopySavedCollateral()
        {
            if(!Complete)throw new InvalidOperationException("Complete correlated supplement required.");
            var result=new byte[AL5ProgrammingWorkflow.CollateralLength];Array.Copy(supplement,result,result.Length);return result;
        }
        public byte[] AssembleSavedSnapshot(byte[] calibration)=>AL5SavedReadCoverage.AssembleSavedSnapshot(calibration,CopySavedSupplement());
    }
}

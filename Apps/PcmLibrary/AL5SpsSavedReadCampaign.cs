// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
namespace PcmHacking
{
    /// <summary>Offline correlation across saved logical segments; no physical session boundary is inferred.</summary>
    public sealed class AL5SpsSavedReadCampaign
    {
        private readonly HashSet<ushort> echoes=new HashSet<ushort>();
        private int? pending;
        public bool Stopped {get;private set;}
        public int SegmentCount {get;private set;}=1;
        public int MatchedDwords {get;private set;}
        public int? LastMatchedAddress {get;private set;}
        public bool HasPendingRequest=>pending.HasValue;
        public bool FreshnessProven=>false;
        public bool FullAddressIdentityProven=>false;
        public bool PhysicalBoundaryProven=>false;
        public bool LiveReadEnabled=>false;
        public bool LiveWriteEnabled=>false;
        public AL5SpsSavedReadCampaign(byte[] pinnedSpsOs) {AL5SpsSavedFlashCoverage.ValidateSource(pinnedSpsOs);}
        public void StartLogicalSegment()
        {
            if(Stopped || pending.HasValue)throw new InvalidOperationException("Logical boundary cannot clear pending/stopped work.");
            SegmentCount++; // Echo history deliberately survives software/session-label changes.
        }
        public void BeginSavedRequest(int address)
        {
            if(Stopped || pending.HasValue)throw new InvalidOperationException("No pending slot or campaign stopped.");
            if(!AL5SpsSavedFlashCoverage.PermissionAllowsDword(address))throw new ArgumentOutOfRangeException(nameof(address));
            if(!echoes.Add((ushort)address)){Stopped=true;throw new InvalidOperationException("Echo reused across campaign; bank or retry identity cannot be proved.");}
            pending=address;
        }
        public AL5SavedReplyKind ObserveSavedReply(byte[] message,out byte[] data,out byte? reason)
        {
            if(Stopped || !pending.HasValue)throw new InvalidOperationException("No pending saved request owns the response.");
            var kind=AL5SavedMode23Reply.ParseForEcho(pending.Value,message,out data,out reason);
            if(kind==AL5SavedReplyKind.MatchingLow16Echo){LastMatchedAddress=pending;pending=null;MatchedDwords++;}
            else if(kind==AL5SavedReplyKind.Negative || kind==AL5SavedReplyKind.Malformed){pending=null;Stopped=true;}
            return kind;
        }
        public void TimeoutOrCancel(){pending=null;Stopped=true;}
    }
}

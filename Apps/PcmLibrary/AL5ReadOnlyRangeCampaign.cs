// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    /// <summary>Owns sequential offline correlation and retained bytes for one bounded flash interval.</summary>
    internal sealed class AL5ReadOnlyRangeCampaign
    {
        private readonly AL5ReadOnlyCoreSession session;
        private readonly uint start;
        private readonly byte[] bytes;
        internal AL5ReadOnlyRangeCampaign(AL5ReadOnlyCoreSession session,uint start,int length)
        {
            if(session==null)throw new ArgumentNullException(nameof(session));
            if(length<=0 || start>0xFFFFF || (uint)length>0x100000-start)throw new ArgumentOutOfRangeException();
            this.session=session;this.start=start;bytes=new byte[length];
        }
        internal int BytesObserved {get;private set;}
        internal int MatchedReplies {get;private set;}
        internal bool Complete => BytesObserved==bytes.Length && !Stopped;
        internal bool Stopped => session.Stopped;
        internal bool HasPendingRequest => session.HasPendingRequest;
        internal byte[] BeginNextSavedVpwRequest()
        {
            if(Complete || Stopped)throw new InvalidOperationException("Offline campaign is closed.");
            return session.BeginSavedVpwRead(start+(uint)BytesObserved,Math.Min(32,bytes.Length-BytesObserved));
        }
        internal AL5ReadOnlyCoreReply ObserveSavedVpwReply(byte[] frame)
        {
            var result=session.ObserveSavedVpwReply(frame,out var observed);
            if(result==AL5ReadOnlyCoreReply.Matched)
            {
                Array.Copy(observed,0,bytes,BytesObserved,observed.Length);
                BytesObserved+=observed.Length;MatchedReplies++;
            }
            return result;
        }
        internal void TimeoutOrCancel()
        {
            if(Complete || Stopped)throw new InvalidOperationException("Offline campaign is closed.");
            session.TimeoutOrCancel();
        }
        internal byte[] CopySavedBytes()=>CopySavedRange(0,bytes.Length);
        internal byte[] CopySavedRange(int offset,int length)
        {
            if(!Complete)throw new InvalidOperationException("Complete correlated coverage required; unknown bytes cannot be filled.");
            if(offset<0 || length<=0 || offset>bytes.Length-length)throw new ArgumentOutOfRangeException();
            var copy=new byte[length];Array.Copy(bytes,offset,copy,0,length);return copy;
        }
    }
}

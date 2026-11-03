// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    /// <summary>Caller-selected model budgets. No values are inferred as physical firmware deadlines.</summary>
    public sealed class AL5OfflineWriteTimeBudget
    {
        public AL5OfflineWriteTimeBudget(TimeSpan send,TimeSpan controlReply,TimeSpan eraseReply,
            TimeSpan dataReply,TimeSpan finalizationReply,TimeSpan totalSession)
        {
            foreach(var value in new[]{send,controlReply,eraseReply,dataReply,finalizationReply,totalSession})
                if(value<=TimeSpan.Zero)throw new ArgumentOutOfRangeException(nameof(send),"All model budgets must be positive.");
            Send=send;ControlReply=controlReply;EraseReply=eraseReply;DataReply=dataReply;
            FinalizationReply=finalizationReply;TotalSession=totalSession;
        }
        public TimeSpan Send { get; }
        public TimeSpan ControlReply { get; }
        public TimeSpan EraseReply { get; }
        public TimeSpan DataReply { get; }
        public TimeSpan FinalizationReply { get; }
        public TimeSpan TotalSession { get; }
        public bool PhysicalDeadlinesQualified => false;
        internal TimeSpan ReplyBudget(AL5OfflineWriteDispatch owner)
        {
            if(owner.Kind==AL5OfflineDispatchKind.Erase)return EraseReply;
            if(owner.Kind==AL5OfflineDispatchKind.Data || owner.Kind==AL5OfflineDispatchKind.ChecksumRetry)return DataReply;
            if(owner.Kind==AL5OfflineDispatchKind.Finalization)return FinalizationReply;
            return ControlReply;
        }
    }
}

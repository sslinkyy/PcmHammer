// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    /// <summary>Explicit saved-session review limits, not measured controller deadlines.</summary>
    public sealed class AL5OfflineCleanupPollPolicy
    {
        public AL5OfflineCleanupPollPolicy(int maximumAttempts,TimeSpan totalWindow)
        {
            if(maximumAttempts<1)throw new ArgumentOutOfRangeException(nameof(maximumAttempts));
            if(totalWindow<=TimeSpan.Zero)throw new ArgumentOutOfRangeException(nameof(totalWindow));
            MaximumAttempts=maximumAttempts;TotalWindow=totalWindow;
        }
        public int MaximumAttempts { get; }
        public TimeSpan TotalWindow { get; }
        public bool PhysicalDeadlinesQualified=>false;
    }
}

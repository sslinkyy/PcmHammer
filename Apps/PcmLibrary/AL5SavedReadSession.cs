// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;

namespace PcmHacking
{
    /// <summary>
    /// Offline correlation rehearsal. Never establishes freshness on the physical bus.
    /// One pending request; no retries or low-16 echo reuse within this instance.
    /// </summary>
    public sealed class AL5SavedReadSession
    {
        private readonly HashSet<ushort> usedEchoes = new HashSet<ushort>();
        private int? pendingAddress;
        public bool Stopped { get; private set; }
        public int MatchedDwords { get; private set; }
        public bool FreshnessProven => false;
        public bool LiveReadEnabled => false;
        public bool HasPendingRequest => pendingAddress.HasValue;

        public void Begin(int address)
        {
            if (Stopped || pendingAddress.HasValue)
                throw new InvalidOperationException("Session stopped or request already pending.");
            // Share address validation with the strict saved-reply parser.
            AL5SavedMode23Reply.Parse(address, Array.Empty<byte>(), out _, out _);
            if (!usedEchoes.Add((ushort)address))
            {
                Stopped = true;
                throw new InvalidOperationException("Low-16 echo already used; delayed replies cannot be distinguished.");
            }
            pendingAddress = address;
        }

        public AL5SavedReplyKind Observe(byte[] message, out byte[] data, out byte? reason)
        {
            if (Stopped || !pendingAddress.HasValue)
                throw new InvalidOperationException("No active request can own this response.");
            var kind = AL5SavedMode23Reply.Parse(pendingAddress.Value, message, out data, out reason);
            if (kind == AL5SavedReplyKind.MatchingLow16Echo)
            {
                MatchedDwords++;
                pendingAddress = null;
            }
            else if (kind == AL5SavedReplyKind.Negative || kind == AL5SavedReplyKind.Malformed)
            {
                Stopped = true;
                pendingAddress = null;
            }
            return kind;
        }

        public void TimeoutOrCancel()
        {
            Stopped = true;
            pendingAddress = null;
        }
    }
}

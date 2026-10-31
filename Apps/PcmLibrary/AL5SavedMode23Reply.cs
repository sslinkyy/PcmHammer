// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    public enum AL5SavedReplyKind { MatchingLow16Echo, Negative, Unrelated, Malformed }

    /// <summary>Strict offline parser. A matching low-16 echo never proves the requested bank.</summary>
    public static class AL5SavedMode23Reply
    {
        public static bool FullAddressIdentityProven => false;
        public static bool ExtendedLiveReadEnabled => false;

        public static AL5SavedReplyKind Parse(int requestedAddress, byte[] message, out byte[] data, out byte? negativeReason)
        {
            if(requestedAddress<AL5CalibrationInspection.StartAddress || requestedAddress>AL5SavedReadCoverage.LastDwordAddress || requestedAddress%4!=0)
                throw new ArgumentOutOfRangeException(nameof(requestedAddress));
            if(message==null)throw new ArgumentNullException(nameof(message));
            data=Array.Empty<byte>();negativeReason=null;
            if(message.Length<4)return AL5SavedReplyKind.Malformed;
            if(message[0]!=0x6C || message[1]!=0xF0 || message[2]!=0x18)return AL5SavedReplyKind.Unrelated;
            if(message[3]==0x7F)
            {
                if(message.Length!=6)return AL5SavedReplyKind.Malformed;
                if(message[4]!=0x23)return AL5SavedReplyKind.Unrelated;
                negativeReason=message[5];return AL5SavedReplyKind.Negative;
            }
            if(message[3]!=0x63)return AL5SavedReplyKind.Unrelated;
            if(message.Length!=10)return AL5SavedReplyKind.Malformed;
            if(message[4]!=(byte)(requestedAddress>>8) || message[5]!=(byte)requestedAddress)return AL5SavedReplyKind.Unrelated;
            data=new byte[4];Buffer.BlockCopy(message,6,data,0,4);
            return AL5SavedReplyKind.MatchingLow16Echo;
        }
    }
}

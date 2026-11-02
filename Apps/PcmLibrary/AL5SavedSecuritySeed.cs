// SPDX-License-Identifier: GPL-3.0-only
using System;
namespace PcmHacking
{
    public enum AL5SavedSeedKind { Unrelated, Malformed, Seed, Short37Unqualified }
    /// <summary>Saved AL5 seed interpretation only. No key generator, sender or authorization inference.</summary>
    public sealed class AL5SavedSecuritySeed
    {
        private AL5SavedSecuritySeed(AL5SavedSeedKind kind,ushort? seed=null){Kind=kind;Seed=seed;}
        public AL5SavedSeedKind Kind { get; }
        public ushort? Seed { get; }
        public bool SecurityAuthorizationProven => false;
        public bool GeneralFreshSeedSupportVerified => false;
        public bool LiveSecuritySubmissionEnabled => false;
        public static AL5SavedSecuritySeed Parse(byte[] frame)
        {
            if(frame==null)throw new ArgumentNullException(nameof(frame));
            if(frame.Length<5 || frame[0]!=0x6C || frame[1]!=0xF0 || frame[2]!=0x18 || frame[3]!=0x67 || frame[4]!=1)
                return new AL5SavedSecuritySeed(AL5SavedSeedKind.Unrelated);
            if(frame.Length==6 && frame[5]==0x37)return new AL5SavedSecuritySeed(AL5SavedSeedKind.Short37Unqualified);
            if(frame.Length!=7)return new AL5SavedSecuritySeed(AL5SavedSeedKind.Malformed);
            return new AL5SavedSecuritySeed(AL5SavedSeedKind.Seed,(ushort)((frame[5]<<8)|frame[6]));
        }
    }
}

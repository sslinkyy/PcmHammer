// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections;
using System.Security.Cryptography;
namespace PcmHacking
{
    /// <summary>Saved four-byte observations for the pinned SPS OS. Unknown bytes are never synthesized.</summary>
    public sealed class AL5SpsSavedFlashCoverage
    {
        private readonly byte[] values=new byte[0x100000];
        private readonly BitArray known=new BitArray(0x100000);
        public int KnownByteCount { get; private set; }
        public int UnknownByteCount => values.Length-KnownByteCount;
        public bool FullImageAvailable => KnownByteCount==values.Length;
        public bool ExtendedLiveReadEnabled => false;
        public bool FullAddressIdentityProven => false;
        public bool FreshnessProven => false;
        public bool LiveWriteEnabled => false;
        public AL5SpsSavedFlashCoverage(byte[] spsOs) { ValidateSource(spsOs); }
        internal static void ValidateSource(byte[] spsOs)
        {
            if(spsOs==null)throw new ArgumentNullException(nameof(spsOs));
            if(spsOs.Length!=679828)throw new ArgumentException("Exact saved SPS OS required.");
            using(var hash=SHA256.Create())
                if(BitConverter.ToString(hash.ComputeHash(spsOs)).Replace("-", "").ToLowerInvariant()!=
                   "145d0dde8c4de88e3145b5693685ab28958d1dda70743c589cc0c7deaa4b45e7")
                    throw new ArgumentException("SPS OS identity mismatch.");
        }
        // Static permission only; dispatcher, correlation and physical reception remain separate gates.
        public static bool PermissionAllowsDword(int address) => address>=0 && address<=0xFFFFC &&
            !(address<0x3FDC && address+4>0x3FD8) && !(address<0xC4C68 && address+4>0xC4C66);
        public bool ObserveSavedDword(int address,byte[] data)
        {
            if(data==null)throw new ArgumentNullException(nameof(data));
            if(data.Length!=4 || !PermissionAllowsDword(address))throw new ArgumentException("Outside pinned Mode 23 permission profile.");
            // Validate the complete overlap before committing any new byte.
            for(int i=0;i<4;i++)if(known[address+i] && values[address+i]!=data[i])throw new ArgumentException("Conflicting saved observations; no overwrite.");
            bool added=false;
            for(int i=0;i<4;i++)if(!known[address+i]){values[address+i]=data[i];known[address+i]=true;KnownByteCount++;added=true;}
            return added;
        }
        public int UnknownBytesInRange(int start,int length)
        {
            Bounds(start,length);int count=0;for(int i=start;i<start+length;i++)if(!known[i])count++;return count;
        }
        public byte[] CopyKnownRange(int start,int length)
        {
            if(UnknownBytesInRange(start,length)!=0)throw new InvalidOperationException("Missing bytes cannot be filled from expected modules, zeros or FF.");
            var copy=new byte[length];Buffer.BlockCopy(values,start,copy,0,length);return copy;
        }
        private static void Bounds(int start,int length)
        {
            if(start<0 || length<=0 || start>0x100000-length)throw new ArgumentOutOfRangeException();
        }
    }
}

// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Security.Cryptography;

namespace PcmHacking
{
    public enum AL5SavedExternalByteOrder { CpuBytes, Swap16 }
    /// <summary>Owned file bytes only. Equality and selected representation do not prove physical reads.</summary>
    public sealed class AL5SavedExternalFlashPair
    {
        private readonly byte[] first,second,canonical;
        public AL5SavedExternalFlashPair(byte[] firstRaw,byte[] secondRaw,AL5SavedExternalByteOrder representation)
        {
            if(firstRaw==null || secondRaw==null)throw new ArgumentNullException();
            if(firstRaw.Length!=0x100000 || secondRaw.Length!=0x100000)throw new ArgumentException("Two complete 1 MiB raw chip files required.");
            if(!Enum.IsDefined(typeof(AL5SavedExternalByteOrder),representation))throw new ArgumentOutOfRangeException(nameof(representation));
            first=(byte[])firstRaw.Clone();second=(byte[])secondRaw.Clone();
            for(int i=0;i<first.Length;i++)if(first[i]!=second[i])throw new ArgumentException("Raw chip files differ; no output image is synthesized.");
            canonical=(byte[])first.Clone();
            if(representation==AL5SavedExternalByteOrder.Swap16)
                for(int i=0;i<canonical.Length;i+=2){byte t=canonical[i];canonical[i]=canonical[i+1];canonical[i+1]=t;}
            Representation=representation;FirstRawSha256=Hash(first);SecondRawSha256=Hash(second);CanonicalSha256=Hash(canonical);
            bool blank=true,zero=true;foreach(byte b in canonical){blank&=b==255;zero&=b==0;}AllFF=blank;AllZero=zero;
        }
        private static string Hash(byte[] b){using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(b)).Replace("-","").ToLowerInvariant();}
        public AL5SavedExternalByteOrder Representation { get; }
        public string FirstRawSha256 { get; }
        public string SecondRawSha256 { get; }
        public string CanonicalSha256 { get; }
        public bool AllFF { get; }
        public bool AllZero { get; }
        public byte[] CopyFirstRaw()=>(byte[])first.Clone();
        public byte[] CopySecondRaw()=>(byte[])second.Clone();
        public byte[] CopyCanonical()=>(byte[])canonical.Clone();
        public bool IndependentPhysicalReadsVerified=>false;
        public bool PhysicalByteOrderVerified=>false;
        public bool SnapshotCoherenceVerified=>false;
        public bool LiveWriteEnabled=>false;
    }
}

// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Security.Cryptography;

namespace PcmHacking
{
    /// <summary>Two independently owned saved epochs, never proof of physical acquisition.</summary>
    public sealed class AL5PreparedBankReference
    {
        public const int StartAddress=0x4000,Length=0x4000;
        private readonly byte[] original,prepared;
        public AL5PreparedBankReference(byte[] originalBanks,byte[] preparedBanks)
        {
            if(originalBanks==null || preparedBanks==null)throw new ArgumentNullException();
            if(originalBanks.Length!=Length || preparedBanks.Length!=Length)throw new ArgumentException("Both saved bank epochs require all 16,384 bytes.");
            original=(byte[])originalBanks.Clone();prepared=(byte[])preparedBanks.Clone();
            OriginalSha256=Hash(original);PreparedSha256=Hash(prepared);
            for(int i=0;i<Length;i++)if(original[i]!=prepared[i])ChangedBytes++;
        }
        private static string Hash(byte[] bytes){using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();}
        public string OriginalSha256 { get; }
        public string PreparedSha256 { get; }
        public int ChangedBytes { get; }
        public bool PhysicalAcquisitionVerified=>false;
        public byte[] CopyOriginal()=>(byte[])original.Clone();
        public byte[] CopyPrepared()=>(byte[])prepared.Clone();
    }
}

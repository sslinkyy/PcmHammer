// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Security.Cryptography;

namespace PcmHacking
{
    /// <summary>EFILive-profile offline construction; explicit collateral is mandatory, never synthesized.</summary>
    public sealed class AL5EfiOfflineWritePlan
    {
        private readonly byte[] candidate;
        private readonly byte[][] requests;
        public const int ProgramBlocks = 192;
        public int RequestCount => ProgramBlocks+3;
        public string LoaderSha256 { get; }
        public string CollateralSha256 { get; }
        public bool LiveUploadEnabled => false;
        public bool LiveExecutionEnabled => false;
        public bool LiveWriteEnabled => false;
        public bool ReadyToFlash => false;
        public bool IndependentCollateralBackupVerified => false;
        public bool PhysicalReadbackVerified => false;
        public bool RecoveryVerified => false;
        public bool AutomaticRetryEnabled => false;

        public AL5EfiOfflineWritePlan(byte[] loader,string loaderSha256,byte[] calibration,byte[] collateral)
        {
            if(loader==null || calibration==null || collateral==null)throw new ArgumentNullException();
            if(loader.Length!=1590 || calibration.Length!=AL5CalibrationInspection.Length || collateral.Length!=AL5ProgrammingWorkflow.CollateralLength)
                throw new ArgumentException("Exact EFILive loader, calibration and explicit 40,998-byte collateral reference required.");
            loader=(byte[])loader.Clone();candidate=(byte[])calibration.Clone();collateral=(byte[])collateral.Clone();
            LoaderSha256=Hash(loader);CollateralSha256=Hash(collateral);
            if(!String.Equals(LoaderSha256,loaderSha256,StringComparison.OrdinalIgnoreCase))throw new ArgumentException("Loader digest mismatch.");
            if(!AL5CalibrationInspection.Inspect(candidate).ChecksPass)throw new ArgumentException("Calibration native checksum/anchor validation failed.");
            // This is the transferred span only. The completion marker is intentionally absent.
            var data=new byte[AL5CapturedProgramImage.EndAddressExclusive-AL5CapturedProgramImage.StartAddress];
            Array.Copy(candidate,0,data,0,candidate.Length);Array.Copy(collateral,0,data,candidate.Length,collateral.Length);
            requests=new byte[RequestCount][];
            requests[0]=Encode(loader,0,loader.Length,0x80,0xFF9000);
            requests[1]=new byte[]{0x6C,0x18,0xF0,0x36,0xEE};
            for(int block=0;block<ProgramBlocks;block++)
            {
                int offset=block*512;int count=Math.Min(512,data.Length-offset);
                requests[block+2]=Encode(data,offset,count,0,(uint)(AL5CapturedProgramImage.StartAddress+offset));
            }
            requests[RequestCount-1]=new byte[]{0x6C,0x18,0xF0,0x36,0xFF};
        }
        private static string Hash(byte[] data)
        {using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(data)).Replace("-", "").ToLowerInvariant();}
        private static byte[] Encode(byte[] data,int offset,int count,byte subtype,uint address)
        {
            var m=new byte[count+12];m[0]=0x6D;m[1]=0x18;m[2]=0xF0;m[3]=0x36;m[4]=subtype;
            m[5]=(byte)(count>>8);m[6]=(byte)count;m[7]=(byte)(address>>16);m[8]=(byte)(address>>8);m[9]=(byte)address;
            Array.Copy(data,offset,m,10,count);int sum=0;for(int i=4;i<m.Length-2;i++)sum+=m[i];
            m[m.Length-2]=(byte)(sum>>8);m[m.Length-1]=(byte)sum;return m;
        }
        public byte[] CopyCalibration()=>(byte[])candidate.Clone();
        public byte[] CopyRequest(int index)
        {if(index<0 || index>=RequestCount)throw new ArgumentOutOfRangeException(nameof(index));return (byte[])requests[index].Clone();}
        internal bool Matches(int index,byte[] observed)
        {
            var expected=requests[index];if(expected.Length!=observed.Length)return false;
            for(int i=0;i<expected.Length;i++)if(expected[i]!=observed[i])return false;
            return true;
        }
    }
}

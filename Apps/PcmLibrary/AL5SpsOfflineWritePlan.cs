// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Security.Cryptography;

namespace PcmHacking
{
    public enum AL5SpsOfflineModule { Loader, OperatingSystem, Calibration }

    /// <summary>Bounded SPS-profile serialization for offline validation only. No device or execution backend.</summary>
    public sealed class AL5SpsOfflineWritePlan
    {
        private readonly byte[][] requests;
        public int RequestCount => requests.Length;
        public bool LiveUploadEnabled => false;
        public bool LiveExecutionEnabled => false;
        public bool LiveWriteEnabled => false;
        public bool ReadyToFlash => false;
        public uint OsStart => 0x20000;
        public uint OsEndInclusive => 0xC5F93;
        public uint CalibrationStart => 0x8000;
        public uint CalibrationEndInclusive => 0x15FD7;
        public ushort SavedOsWordSum { get; }
        public ushort SavedCalibrationWordSum { get; }

        public AL5SpsOfflineWritePlan(byte[] loader, string loaderSha256, byte[] os, byte[] calibration)
        {
            if(loader==null || os==null || calibration==null)throw new ArgumentNullException();
            if(loader.Length!=3858)throw new ArgumentException("Exact observed SPS loader length required.");
            if(loaderSha256==null || loaderSha256.Length!=64)throw new ArgumentException("Explicit loader digest required.");
            loader=(byte[])loader.Clone();
            using(var hash=SHA256.Create())
            {
                var actual=BitConverter.ToString(hash.ComputeHash(loader)).Replace("-", "");
                if(!String.Equals(actual,loaderSha256,StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException("Loader digest mismatch.");
            }
            var mapping=new AL5SpsModuleMapping(os,calibration);
            os=mapping.CopyOsModule();calibration=mapping.CopyCalibrationModule();
            SavedOsWordSum=AL5SpsModuleMapping.Sum(os);SavedCalibrationWordSum=AL5SpsModuleMapping.Sum(calibration);
            requests=new byte[181][];
            requests[0]=Encode(loader,0,loader.Length,0x80,0xFF9006);
            for(int i=0;i<166;i++)requests[1+i]=Encode(os,i*4096,4096,0,0xFF8000);
            for(int i=0;i<14;i++)requests[167+i]=Encode(calibration,i*4096,4096,0,0xFF8000);
        }

        private static byte[] Encode(byte[] source,int offset,int count,byte subtype,uint address)
        {
            var m=new byte[count+12];
            m[0]=0x6D;m[1]=0x18;m[2]=0xF0;m[3]=0x36;m[4]=subtype;
            m[5]=(byte)(count>>8);m[6]=(byte)count;
            m[7]=(byte)(address>>16);m[8]=(byte)(address>>8);m[9]=(byte)address;
            Array.Copy(source,offset,m,10,Math.Min(count,source.Length-offset));
            int sum=0;for(int i=4;i<m.Length-2;i++)sum+=m[i];
            m[m.Length-2]=(byte)(sum>>8);m[m.Length-1]=(byte)sum;
            return m;
        }
        private void CheckIndex(int index)
        {if(index<0 || index>=RequestCount)throw new ArgumentOutOfRangeException(nameof(index));}
        public byte[] CopyRequest(int index) {CheckIndex(index);return (byte[])requests[index].Clone();}
        public AL5SpsOfflineModule Module(int index)
        {CheckIndex(index);return index==0?AL5SpsOfflineModule.Loader:index<167?AL5SpsOfflineModule.OperatingSystem:AL5SpsOfflineModule.Calibration;}
        public int DataBytes(int index)
        {CheckIndex(index);return index==0?3858:index==166?3988:index==180?4056:4096;}
        /// <summary>Conditional flash destination from the pinned module profile, never the staging address.</summary>
        public uint? ConditionalFlashAddress(int index)
        {CheckIndex(index);return index==0?(uint?)null:index<167?OsStart+(uint)(index-1)*4096:CalibrationStart+(uint)(index-167)*4096;}
        public bool EndsModule(int index) {CheckIndex(index);return index==166 || index==180;}
        internal bool Matches(int index,byte[] observed)
        {
            CheckIndex(index);var expected=requests[index];
            if(observed.Length!=expected.Length)return false;
            for(int i=0;i<expected.Length;i++)if(observed[i]!=expected[i])return false;
            return true;
        }
    }
}

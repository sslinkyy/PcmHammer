// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Security.Cryptography;
namespace PcmHacking
{
    public enum AL5ReadOnlyCoreReply { Matched, Unrelated, Malformed }
    /// <summary>Experimental offline payloads and VPW envelopes only. No adapter, uploader or execution path.</summary>
    public sealed class AL5ReadOnlyCoreSession
    {
        private readonly byte[] nonce;
        private byte[]? pending;
        private uint sequence;
        public bool Stopped {get;private set;}
        public bool HasPendingRequest=>pending!=null;
        public bool LiveUploadEnabled=>false;
        public bool LiveExecutionEnabled=>false;
        public bool HardwareQualified=>false;
        public bool LiveWriteEnabled=>false;
        public AL5ReadOnlyCoreSession(byte[] nonce)
        {
            if(nonce==null)throw new ArgumentNullException(nameof(nonce));
            if(nonce.Length!=8)throw new ArgumentException("Exact eight-byte offline session nonce required.");
            int n=0;foreach(byte b in nonce)n|=b;if(n==0)throw new ArgumentException("Zero nonce rejected.");
            this.nonce=(byte[])nonce.Clone();
        }
        public static AL5ReadOnlyCoreSession CreateOffline()
        {
            var nonce=new byte[8];using(var rng=RandomNumberGenerator.Create()){do{rng.GetBytes(nonce);}while(Array.TrueForAll(nonce,b=>b==0));}
            return new AL5ReadOnlyCoreSession(nonce);
        }
        public byte[] BeginSavedRead(uint address,int count)
        {
            if(Stopped || pending!=null)throw new InvalidOperationException("No offline pending slot available.");
            if(count<1 || count>32 || address>0xFFFFF || (uint)count>0x100000-address)throw new ArgumentOutOfRangeException();
            if(sequence==uint.MaxValue){Stopped=true;throw new InvalidOperationException("Sequence must not wrap.");}
            sequence++;var r=new byte[22];r[0]=0x41;r[1]=0x52;r[2]=1;r[3]=1;Array.Copy(nonce,0,r,4,8);
            r[12]=(byte)(sequence>>24);r[13]=(byte)(sequence>>16);r[14]=(byte)(sequence>>8);r[15]=(byte)sequence;
            r[16]=(byte)(address>>16);r[17]=(byte)(address>>8);r[18]=(byte)address;r[19]=(byte)count;SetCrc(r);
            pending=r;return (byte[])r.Clone();
        }
        public byte[] BeginSavedVpwRead(uint address,int count)
        {
            var payload=BeginSavedRead(address,count);var frame=new byte[26];
            frame[0]=0x6D;frame[1]=0x18;frame[2]=0xF0;frame[3]=0xB1;
            Array.Copy(payload,0,frame,4,payload.Length);return frame;
        }
        public AL5ReadOnlyCoreReply ObserveSavedVpwReply(byte[] frame,out byte[] data)
        {
            data=Array.Empty<byte>();if(frame==null)throw new ArgumentNullException(nameof(frame));
            if(Stopped || pending==null)throw new InvalidOperationException("No offline pending request.");
            if(frame.Length<4 || frame[0]!=0x6D || frame[1]!=0xF0 || frame[2]!=0x18 || frame[3]!=0xF1)
                return AL5ReadOnlyCoreReply.Unrelated;
            // The adapter's transport CRC is already removed. Internal payload CRC remains mandatory.
            if(frame.Length<27 || frame.Length>58){Stopped=true;pending=null;return AL5ReadOnlyCoreReply.Malformed;}
            var payload=new byte[frame.Length-4];Array.Copy(frame,4,payload,0,payload.Length);
            return ObserveSavedReply(payload,out data);
        }
        public AL5ReadOnlyCoreReply ObserveSavedReply(byte[] reply,out byte[] data)
        {
            data=Array.Empty<byte>();if(reply==null)throw new ArgumentNullException(nameof(reply));
            if(Stopped || pending==null)throw new InvalidOperationException("No offline pending request.");
            if(reply.Length<2 || reply[0]!=0x61 || reply[1]!=0x72)return AL5ReadOnlyCoreReply.Unrelated;
            if(reply.Length<23 || reply.Length>54 || reply[2]!=1 || reply[3]!=0 || reply[19]<1 || reply[19]>32 || reply.Length!=22+reply[19] ||
               Crc(reply,reply.Length-2)!=((reply[reply.Length-2]<<8)|reply[reply.Length-1]))
            {Stopped=true;pending=null;return AL5ReadOnlyCoreReply.Malformed;}
            for(int i=4;i<20;i++)if(reply[i]!=pending[i])return AL5ReadOnlyCoreReply.Unrelated;
            data=new byte[reply[19]];Array.Copy(reply,20,data,0,data.Length);pending=null;return AL5ReadOnlyCoreReply.Matched;
        }
        public void TimeoutOrCancel(){Stopped=true;pending=null;}
        internal static ushort Crc(byte[] data,int count)
        {
            ushort crc=0xFFFF;for(int i=0;i<count;i++){crc^=(ushort)(data[i]<<8);for(int j=0;j<8;j++)crc=(ushort)((crc&0x8000)!=0?(crc<<1)^0x1021:crc<<1);}return crc;
        }
        internal static void SetCrc(byte[] data){ushort c=Crc(data,data.Length-2);data[data.Length-2]=(byte)(c>>8);data[data.Length-1]=(byte)c;}
    }
}

using System;
using System.IO;
using System.Security.Cryptography;
using PcmHacking;
class Program
{
 static void Check(bool b) {if(!b)throw new Exception("Assertion failed");}
 static void Reject(Action a) {try {a();}catch(ArgumentException){return;}catch(InvalidOperationException){return;}throw new Exception("Expected rejection");}
 static string Hash(byte[] b)=>Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();
 static byte[] loader=new byte[3858], os=new byte[679828], cal=new byte[57304];
 static void Long(byte[] b,int p,uint n) {b[p]=(byte)(n>>24);b[p+1]=(byte)(n>>16);b[p+2]=(byte)(n>>8);b[p+3]=(byte)n;}
 static void Balance(byte[] b) {int sum=0;for(int i=0;i<b.Length-2;i+=2)sum=(sum+(b[i]<<8)+b[i+1])&65535;int n=(-sum)&65535;b[b.Length-2]=(byte)(n>>8);b[b.Length-1]=(byte)n;}
 static AL5SpsOfflineRehearsal New()=>new AL5SpsOfflineRehearsal(loader,Hash(loader),os,cal);
 static byte[] Packet(byte[] source,int block=0,bool entry=false)
 {
  int count=entry?3858:4096;var m=new byte[count+12];m[0]=0x6D;m[1]=0x18;m[2]=0xF0;m[3]=0x36;m[4]=(byte)(entry?0x80:0);m[5]=(byte)(count>>8);m[6]=(byte)count;
  m[7]=0xFF;m[8]=(byte)(entry?0x90:0x80);m[9]=(byte)(entry?6:0);
  int start=block*4096;Array.Copy(source,start,m,10,Math.Min(count,source.Length-start));int sum=0;for(int i=4;i<m.Length-2;i++)sum+=m[i];m[m.Length-2]=(byte)(sum>>8);m[m.Length-1]=(byte)sum;return m;
 }
 static byte[] Reply(byte status,bool entry=false)=>new byte[]{0x6C,0xF0,0x18,0x76,(byte)(entry?0x80:0),status};
 static AL5SpsOfflineRehearsal Started(){var x=New();x.ObserveRequest(Packet(loader,0,true));x.ObserveReply(Reply(0x73,true));return x;}
 static void Main(string[] args)
 {
  os[0x23]=1;cal[0x23]=2;Long(os,0x3E,0x20000);Long(os,0x42,0xC5F93);Long(os,0x46,0x8000);Long(os,0x4A,0x15FD7);
  Balance(os);Balance(cal);
  var x=Started();Check(x.OsFillStart==0xC5F94 && x.CalibrationFillStart==0x15FD8 && x.FillWord==0x4AFC);
  x.ObserveRequest(Packet(os));x.ObserveReply(Reply(0x78));Check(x.AcknowledgedBlocks==0);Reject(()=>x.ObserveRequest(Packet(os)));x.ObserveReply(Reply(0x73));Check(x.AcknowledgedBlocks==1);
  foreach(byte status in new byte[]{0x74,0x75,0x77,0x85,0x8A}) {var f=Started();f.ObserveRequest(Packet(os));f.ObserveReply(Reply(status));Check(f.State==AL5SpsOfflineState.Stopped && f.FailureStatus==status);Reject(()=>f.ObserveReply(Reply(0x73)));Reject(()=>f.ObserveRequest(Packet(os)));}
  var bad=Started();var pkt=Packet(os);pkt[10]^=1;Reject(()=>bad.ObserveRequest(pkt));Check(bad.State==AL5SpsOfflineState.BlockRequest);
  var wrong=(byte[])cal.Clone();wrong[0]^=1;Reject(()=>new AL5SpsOfflineRehearsal(loader,Hash(loader),os,wrong));
  Check(x.CopyObservedOsModuleEraseAddresses().Length==16 && x.CopyObservedCalibrationModuleEraseAddresses().Length==2);
  var eraseCopy=x.CopyObservedOsModuleEraseAddresses();eraseCopy[0]=0;Check(x.CopyObservedOsModuleEraseAddresses()[0]==0xF0000);
  var ownership=Started();var changed=Packet(os);changed[10]^=1;int total=0;for(int i=4;i<changed.Length-2;i++)total+=changed[i];changed[changed.Length-2]=(byte)(total>>8);changed[changed.Length-1]=(byte)total;Reject(()=>ownership.ObserveRequest(changed));
  var padding=Started();for(int i=0;i<165;i++){padding.ObserveRequest(Packet(os,i));padding.ObserveReply(Reply(0x73));}var altered=Packet(os,165);altered[4105]=1;total=0;for(int i=4;i<altered.Length-2;i++)total+=altered[i];altered[altered.Length-2]=(byte)(total>>8);altered[altered.Length-1]=(byte)total;Reject(()=>padding.ObserveRequest(altered));
  var early=Started();early.ObserveRequest(Packet(os));early.ObserveReply(Reply(0x86));Check(early.State==AL5SpsOfflineState.Stopped);
  foreach(bool pending in new[]{false,true}) {var f=Started();if(pending)f.ObserveRequest(Packet(os));f.Interrupt();Check(f.State==AL5SpsOfflineState.Stopped);Reject(()=>f.ObserveReply(Reply(0x73)));}
  Reject(()=>new AL5SpsOfflineRehearsal(loader,new string('0',64),os,cal));
  var complete=Started();foreach(var module in new[]{os,cal})for(int i=0;i<(module.Length+4095)/4096;i++){complete.ObserveRequest(Packet(module,i));complete.ObserveReply(Reply(module==cal && i==13?(byte)0x86:(byte)0x73));}
  Check(complete.State==AL5SpsOfflineState.CompletedObservations && complete.AcknowledgedBlocks==180 && !complete.LiveWriteEnabled && !complete.ReadyToFlash && !complete.RecoveryVerified && !complete.PhysicalReadbackVerified);
  Reject(()=>complete.ObserveRequest(Packet(os)));Console.WriteLine("Offline safety, boundaries, failure latch, interruption and 180-block fixture passed.");
  if(args.Length==4)
  {
   var replay=new AL5SpsOfflineRehearsal(File.ReadAllBytes(args[0]),"4a03452ef44e85d1874f6b519f8b3e7fd3c2bca7332ecf11fb1aaaa1b6372d80",File.ReadAllBytes(args[1]),File.ReadAllBytes(args[2]));
   foreach(var line in File.ReadLines(args[3])){var p=line.Split(' ');var m=Convert.FromHexString(p[1]);if(p[0]=="T" && m.Length>4 && m[0]==0x6D && m[1]==0x18 && m[2]==0xF0 && m[3]==0x36)replay.ObserveRequest(m);else if(p[0]=="R" && m.Length>=4 && m[0]==0x6C && m[1]==0xF0 && m[2]==0x18 && m[3]==0x76)replay.ObserveReply(m);}
   Check(replay.State==AL5SpsOfflineState.CompletedObservations && replay.AcknowledgedBlocks==180);Console.WriteLine("Saved SPS capture replay passed: "+replay.AcknowledgedBlocks+" acknowledged blocks, "+replay.PendingReplies+" pending replies.");
  }
 }
}
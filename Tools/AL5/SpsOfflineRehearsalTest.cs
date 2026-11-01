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
  Balance(os);
  Array.Copy(Convert.FromHexString("00E7B058"),0,cal,0x24,4);
  Array.Copy(Convert.FromHexString("11F70C68073E05A0040002D9"),0,cal,0xA996-0x8000,12);
  Array.Copy(Convert.FromHexString("00110009"),0,cal,0x158A8-0x8000,4);
  var field=Convert.FromHexString(AL5CalibrationInspection.Inspect(cal).ComputedChecksumHex!);Array.Copy(field,0,cal,cal.Length-4,4);
  LifecycleTests.Run(loader,os,cal,null);
  var mapping=new AL5SpsModuleMapping(os,cal);var affected=mapping.CopyConditionalAffectedBytes();
  Check(affected.Length==0xF8000 && affected[0x15FD8-0x8000]==0x4A && affected[0x15FD9-0x8000]==0xFC);
  var before=new byte[0x100000];var after=new byte[0x100000];Array.Copy(affected,0,after,0x8000,affected.Length);
  var preservation=mapping.CompareSavedSnapshots(before,after);Check(preservation.SavedProtectedPrefixMatches && preservation.SavedAffectedImageMatches && preservation.OtherFlashWouldChange && !preservation.PhysicalPreservationVerified);
  after[0x4000]=1;preservation=mapping.CompareSavedSnapshots(before,after);Check(!preservation.SavedProtectedPrefixMatches && preservation.PersistentRegionDifferences==1);
  after[0x4000]=0;after[0x15FD8]=0;Check(!mapping.CompareSavedSnapshots(before,after).SavedAffectedImageMatches);
  Reject(()=>mapping.CompareSavedSnapshots(cal,cal));
  var balancedBad=(byte[])cal.Clone();balancedBad[0x100]^=1;Balance(balancedBad);Check(AL5SpsModuleMapping.Sum(balancedBad)==0);Reject(()=>new AL5SpsModuleMapping(os,balancedBad));
  var custom=(byte[])cal.Clone();custom[0x100]^=1;field=Convert.FromHexString(AL5CalibrationInspection.Inspect(custom).ComputedChecksumHex!);Array.Copy(field,0,custom,custom.Length-4,4);
  var customMap=new AL5SpsModuleMapping(os,custom);Check(customMap.CopyCalibrationModule()[0x100]==custom[0x100] && !customMap.LiveWriteEnabled && !customMap.PhysicalSectorMappingVerified);
  var returned=customMap.CopyCalibrationModule();returned[0x100]^=1;Check(customMap.CopyCalibrationModule()[0x100]==custom[0x100]);
  var wrongMetadata=(byte[])os.Clone();Long(wrongMetadata,0x46,0x4000);Balance(wrongMetadata);Reject(()=>new AL5SpsModuleMapping(wrongMetadata,cal));
  var plan=new AL5SpsOfflineWritePlan(loader,Hash(loader),os,cal);
  Check(plan.RequestCount==181 && !plan.LiveUploadEnabled && !plan.LiveExecutionEnabled && !plan.LiveWriteEnabled && !plan.ReadyToFlash);
  Check(plan.Module(0)==AL5SpsOfflineModule.Loader && plan.ConditionalFlashAddress(0)==null);
  Check(plan.ConditionalFlashAddress(1)==0x20000 && plan.ConditionalFlashAddress(166)==0xC5000 && plan.DataBytes(166)==3988);
  Check(plan.ConditionalFlashAddress(167)==0x8000 && plan.ConditionalFlashAddress(180)==0x15000 && plan.DataBytes(180)==4056);
  Check(plan.EndsModule(166) && plan.EndsModule(180) && !plan.EndsModule(0));
  for(int i=0;i<181;i++)Check(Convert.ToHexString(plan.CopyRequest(i))==Convert.ToHexString(i==0?Packet(loader,0,true):i<167?Packet(os,i-1):Packet(cal,i-167)));
  foreach(int i in new[]{-1,181,int.MaxValue}){Reject(()=>plan.CopyRequest(i));Reject(()=>plan.ConditionalFlashAddress(i));Reject(()=>plan.DataBytes(i));Reject(()=>plan.Module(i));Reject(()=>plan.EndsModule(i));}
  foreach(var pair in new[]{(loader,0),(os,1),(cal,167)}){byte saved=pair.Item1[0];pair.Item1[0]^=1;Check(plan.CopyRequest(pair.Item2)[10]==saved);pair.Item1[0]=saved;}
  var detached=plan.CopyRequest(1);detached[10]^=1;Check(plan.CopyRequest(1)[10]!=detached[10]);
  var customPlan=new AL5SpsOfflineWritePlan(loader,Hash(loader),os,custom);
  for(int i=0;i<167;i++)Check(Convert.ToHexString(plan.CopyRequest(i))==Convert.ToHexString(customPlan.CopyRequest(i)));
  var generated=New();for(int i=0;i<plan.RequestCount;i++){Check(Convert.ToHexString(generated.CopyNextOfflineRequest())==Convert.ToHexString(plan.CopyRequest(i)));generated.ObserveRequest(generated.CopyNextOfflineRequest());Reject(()=>generated.CopyNextOfflineRequest());if(i!=0)generated.ObserveReply(Reply(0x78));generated.ObserveReply(Reply(i==180?(byte)0x86:(byte)0x73,i==0));}
  Check(generated.State==AL5SpsOfflineState.CompletedObservations && generated.AcknowledgedBlocks==180 && generated.PendingReplies==180);
  foreach(int boundary in new[]{0,1,166,167,180})foreach(byte status in new byte[]{0x74,0x75,0x77,0x85,0x8A})
  {
   var failed=New();for(int i=0;i<boundary;i++){failed.ObserveRequest(plan.CopyRequest(i));failed.ObserveReply(Reply(0x73,i==0));}
   failed.ObserveRequest(plan.CopyRequest(boundary));failed.ObserveReply(Reply(status,boundary==0));
   Check(failed.State==AL5SpsOfflineState.Stopped && failed.FailureStatus==status);Reject(()=>failed.ObserveRequest(plan.CopyRequest(boundary)));Reject(()=>failed.CopyNextOfflineRequest());
  }
  foreach(int boundary in new[]{0,1,166,167,180})foreach(bool awaitingReply in new[]{false,true})
  {
   var interrupted=New();for(int i=0;i<boundary;i++){interrupted.ObserveRequest(plan.CopyRequest(i));interrupted.ObserveReply(Reply(0x73,i==0));}
   if(awaitingReply)interrupted.ObserveRequest(plan.CopyRequest(boundary));interrupted.Interrupt();
   Check(interrupted.State==AL5SpsOfflineState.Stopped);Reject(()=>interrupted.ObserveRequest(plan.CopyRequest(boundary)));
  }
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
  Reject(()=>complete.CopyNextOfflineRequest());Reject(()=>complete.ObserveRequest(Packet(os)));Console.WriteLine("Offline safety, boundaries, failure latch, interruption and 180-block fixture passed.");
  if(args.Length==4 || args.Length==5)
  {
   LifecycleTests.Run(File.ReadAllBytes(args[0]),File.ReadAllBytes(args[1]),File.ReadAllBytes(args[2]),args[3]);
   var actualMap=new AL5SpsModuleMapping(File.ReadAllBytes(args[1]),File.ReadAllBytes(args[2]));
   if(args.Length==5)Check(Convert.ToHexString(SHA256.HashData(actualMap.CopyCalibrationModule()))==Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(args[4]))));
   var replay=new AL5SpsOfflineRehearsal(File.ReadAllBytes(args[0]),"4a03452ef44e85d1874f6b519f8b3e7fd3c2bca7332ecf11fb1aaaa1b6372d80",File.ReadAllBytes(args[1]),File.ReadAllBytes(args[2]));
   var actualPlan=new AL5SpsOfflineWritePlan(File.ReadAllBytes(args[0]),"4a03452ef44e85d1874f6b519f8b3e7fd3c2bca7332ecf11fb1aaaa1b6372d80",File.ReadAllBytes(args[1]),File.ReadAllBytes(args[2]));int actualIndex=0;
   foreach(var line in File.ReadLines(args[3])){var p=line.Split(' ');var m=Convert.FromHexString(p[1]);if(p[0]=="T" && m.Length>4 && m[0]==0x6D && m[1]==0x18 && m[2]==0xF0 && m[3]==0x36){Check(Convert.ToHexString(actualPlan.CopyRequest(actualIndex++))==Convert.ToHexString(m));replay.ObserveRequest(m);}else if(p[0]=="R" && m.Length>=4 && m[0]==0x6C && m[1]==0xF0 && m[2]==0x18 && m[3]==0x76)replay.ObserveReply(m);}
   Check(actualIndex==181 && replay.State==AL5SpsOfflineState.CompletedObservations && replay.AcknowledgedBlocks==180);Console.WriteLine("All 181 generated transfers exactly match the saved SPS capture.");Console.WriteLine("Saved SPS capture replay passed: "+replay.AcknowledgedBlocks+" acknowledged blocks, "+replay.PendingReplies+" pending replies.");
  }
 }
}
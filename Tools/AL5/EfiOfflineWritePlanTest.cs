using System;
using System.Linq;
using System.Security.Cryptography;
using PcmHacking;

static class EfiOfflineWritePlanTest
{
 static void Check(bool value){if(!value)throw new Exception("EFILive offline plan assertion failed");}
 static void Reject(Action action){try{action();}catch(ArgumentException){return;}catch(InvalidOperationException){return;}throw new Exception("Expected offline rejection");}
 static byte[] Bytes(string line)=>Convert.FromHexString(line.Substring(2));
 static bool ProgramFrame(string line)=>line.StartsWith("T 6d18f03600",StringComparison.Ordinal);
 public static void Run(string[] lines,byte[] calibration,string loaderHash)
 {
  byte[] loader=Bytes(lines.Single(l=>l.StartsWith("T 6d18f03680"))).Skip(10).Take(1590).ToArray();
  var image=new AL5CapturedProgramImage();foreach(var line in lines.Where(ProgramFrame))image.Observe(Bytes(line));
  // Explicit CAPTURE-derived reference, deliberately not represented as an independent physical backup.
  byte[] collateral=image.CopyCompleteImage().Skip(calibration.Length).ToArray();
  var plan=new AL5EfiOfflineWritePlan(loader,loaderHash,calibration,collateral);
  Check(plan.RequestCount==195 && collateral.Length==40998 && plan.CopyRequest(193).Length==522);
  Check(plan.CollateralSha256==Convert.ToHexString(SHA256.HashData(collateral)).ToLowerInvariant());
  Check(!plan.IndependentCollateralBackupVerified && !plan.PhysicalReadbackVerified && !plan.ReadyToFlash && !plan.RecoveryVerified && !plan.LiveUploadEnabled && !plan.LiveExecutionEnabled && !plan.LiveWriteEnabled && !plan.AutomaticRetryEnabled);
  Reject(()=>new AL5EfiOfflineWritePlan(loader,loaderHash,calibration,Array.Empty<byte>()));
  Reject(()=>new AL5EfiOfflineWritePlan(loader,loaderHash,calibration,new byte[41000]));
  Reject(()=>new AL5EfiOfflineWritePlan(loader,new string('0',64),calibration,collateral));
  Reject(()=>plan.CopyRequest(-1));Reject(()=>plan.CopyRequest(195));
  var detached=plan.CopyRequest(2);detached[10]^=1;Check(plan.CopyRequest(2)[10]!=detached[10]);
  var collateralPacket=plan.CopyRequest(113);collateral[0]^=1;Check(plan.CopyRequest(113).SequenceEqual(collateralPacket));collateral[0]^=1;
  var otherCollateral=(byte[])collateral.Clone();otherCollateral[0]^=1;otherCollateral[otherCollateral.Length-1]^=1;
  var otherPlan=new AL5EfiOfflineWritePlan(loader,loaderHash,calibration,otherCollateral);
  Check(otherPlan.CopyRequest(113)[10+calibration.Length%512]==otherCollateral[0]);
  Check(otherPlan.CopyRequest(193)[519]==otherCollateral[otherCollateral.Length-1]);
  Check(otherPlan.CollateralSha256!=plan.CollateralSha256);
  var last=plan.CopyRequest(193);Check(last[7]==1 && last[8]==0xFE && last[9]==0 && last[5]==1 && last[6]==0xFE);
  foreach(var pair in new[]{(loader,0),(calibration,2)}){byte saved=pair.Item1[0];pair.Item1[0]^=1;Check(plan.CopyRequest(pair.Item2)[10]==saved);pair.Item1[0]=saved;}
  var custom=(byte[])calibration.Clone();custom[0x100]^=1;
  var field=Convert.FromHexString(AL5CalibrationInspection.Inspect(custom).ComputedChecksumHex!);Array.Copy(field,0,custom,custom.Length-4,4);
  var customPlan=new AL5EfiOfflineWritePlan(loader,loaderHash,custom,collateral);
  Check(!plan.CopyRequest(2).SequenceEqual(customPlan.CopyRequest(2)));
  for(int i=114;i<195;i++)Check(plan.CopyRequest(i).SequenceEqual(customPlan.CopyRequest(i)));
  Check(plan.CopyRequest(0).SequenceEqual(customPlan.CopyRequest(0)) && plan.CopyRequest(1).SequenceEqual(customPlan.CopyRequest(1)));
  var session=new AL5CapturedWriteRehearsal(plan);Reject(()=>session.CopyNextOfflineRequest());
  var unique=new System.Collections.Generic.HashSet<int>();int matched=0,repeated=0;
  foreach(var line in lines)
  {
   byte[] m=Bytes(line);int index=-1;
   if(line.StartsWith("T 6d18f03680"))index=0;
   else if(line=="T 6c18f036ee")index=1;
   else if(line=="T 6c18f036ff")index=194;
   else if(ProgramFrame(line))index=2+(((m[7]<<16)|(m[8]<<8)|m[9])-0x8000)/512;
   if(index>=0)
   {
    Check(plan.CopyRequest(index).SequenceEqual(m));matched++;
    if(unique.Add(index))
    {
     Check(session.CopyNextOfflineRequest().SequenceEqual(m));
     if(index==114)
     {
      // Rebalanced transport checksum cannot conceal a changed collateral payload.
      var bad=(byte[])m.Clone();bad[10]^=1;int sum=0;for(int i=4;i<bad.Length-2;i++)sum+=bad[i];bad[bad.Length-2]=(byte)(sum>>8);bad[bad.Length-1]=(byte)sum;
      Reject(()=>session.Observe(true,bad));Check(session.CopyNextOfflineRequest().SequenceEqual(m));
     }
    }
    else {repeated++;Reject(()=>session.CopyNextOfflineRequest());}
   }
   session.Observe(line[0]=='T',m);
  }
  Check(unique.Count==195 && session.PositiveProgramReplies==192 && session.State==AL5CapturedWriteState.AwaitingSavedVerification);
  Reject(()=>session.CopyNextOfflineRequest());
  Check(!session.LiveWriteEnabled && !session.LiveUploadEnabled && !session.LiveExecutionEnabled && !session.AutomaticRetryEnabled);
  foreach(string trigger in new[]{"T 6c18f036ee","T 6c18f036ff",lines.First(ProgramFrame)})
  {
   int boundary=Array.IndexOf(lines,trigger);Check(boundary>=0);
   foreach(byte status in trigger==lines.First(ProgramFrame)?new byte[]{0x77,0xF8}:new byte[]{0x85,0xF8,0xFF})
   {
    var failed=new AL5CapturedWriteRehearsal(plan);for(int i=0;i<=boundary;i++)failed.Observe(lines[i][0]=='T',Bytes(lines[i]));
    Reject(()=>failed.CopyNextOfflineRequest());
    failed.Observe(false,new byte[]{trigger==lines.First(ProgramFrame)?(byte)0x6D:(byte)0x6C,0xF0,0x18,0x76,0,status});
    Reject(()=>failed.CopyNextOfflineRequest());
    if(status!=0x77)Check(failed.State==AL5CapturedWriteState.Stopped);
    failed.Interrupt();Check(failed.State==AL5CapturedWriteState.Stopped);
   }
  }
  Console.WriteLine($"PASS EFILive constructed plan: {unique.Count} distinct requests, {matched} exact captured matches, {repeated} observed repeats; explicit capture-derived collateral remains physically unverified.");
 }
}

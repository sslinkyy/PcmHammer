using System;
using System.IO;
using System.Security.Cryptography;
using PcmHacking;

static class LifecycleTests
{
 static void Check(bool b){if(!b)throw new Exception("Lifecycle assertion failed");}
 static void Closed(Action a){try{a();}catch(InvalidOperationException){return;}throw new Exception("Closed lifecycle accepted an operation");}
 static readonly string[] setup={"T 6cfef02800","R 6cf0186800","T 6c18f02701","R 6cf01867011234","T 6c18f027025678","R 6cf018670234","T 6cfef02800","R 6cf0186800","T 6c18f034","R 6cf0187444","T 6cfef0a0","R 6cf018e0aa","T 6cfef0a1","T 6c18f034","R 6cf0187444"};
 static readonly string[] cleanup={"T 6cfef02800","R 6cf0186800","T 6c18f02701","R 6cf018670137","T 6c18f02701","R 6cf01867011234","T 6c18f027025678","R 6cf018670234","T 6cfef02800","R 6cf0186800"};
 static AL5SpsSavedFrameDisposition Observe(AL5SpsOfflineLifecycle s,string line)=>s.ObserveSavedFrame(line[0]=='T',Convert.FromHexString(line.Substring(2)));
 static void Setup(AL5SpsOfflineLifecycle s){foreach(var line in setup)Check(Observe(s,line)==AL5SpsSavedFrameDisposition.Advanced);}
 static void Program(AL5SpsOfflineLifecycle s,AL5SpsOfflineWritePlan plan)
 {
  for(int i=0;i<plan.RequestCount;i++)
  {
   Check(Convert.ToHexString(s.CopyNextOfflineProgrammingRequest())==Convert.ToHexString(plan.CopyRequest(i)));
   Check(s.ObserveSavedFrame(true,s.CopyNextOfflineProgrammingRequest())==AL5SpsSavedFrameDisposition.Pending);
   Closed(()=>s.CopyNextOfflineProgrammingRequest());
   if(i!=0)Check(Observe(s,"R 6cf018760078")==AL5SpsSavedFrameDisposition.Pending);
   Check(Observe(s,i==0?"R 6cf018768073":i==180?"R 6cf018760086":"R 6cf018760073")==AL5SpsSavedFrameDisposition.Advanced);
  }
 }
 public static void Run(byte[] loader,byte[] os,byte[] cal,string? corpus)
 {
  var hash=Convert.ToHexString(SHA256.HashData(loader));
  AL5SpsOfflineLifecycle New()=>new AL5SpsOfflineLifecycle(loader,hash,os,cal);
  var plan=new AL5SpsOfflineWritePlan(loader,hash,os,cal);
  var s=New();Closed(()=>s.CopyNextOfflineProgrammingRequest());
  Check(Observe(s,"R 6cf0106800")==AL5SpsSavedFrameDisposition.Unrelated);
  Check(Observe(s,"T 8cfef03f")==AL5SpsSavedFrameDisposition.KeepAlive);
  Check(s.SetupObservations==0);Setup(s);Program(s,plan);
  Check(s.Phase==AL5SpsOfflinePhase.Cleanup && s.AcknowledgedBlocks==180);Closed(()=>s.CopyNextOfflineProgrammingRequest());
  foreach(var line in cleanup)Check(Observe(s,line)==AL5SpsSavedFrameDisposition.Advanced);
  Check(s.Phase==AL5SpsOfflinePhase.CompletedObservations && s.SetupObservations==15 && s.CleanupObservations==10);
  Check(!s.LiveUploadEnabled && !s.LiveExecutionEnabled && !s.LiveWriteEnabled && !s.IdentityWritesEnabled && !s.SecurityAuthorizationProven && !s.PhysicalReadbackVerified && !s.RecoveryVerified && !s.ReadyToFlash && !s.AutomaticRetryEnabled);
  Closed(()=>Observe(s,"T 6c18f03b01004141414141"));Closed(()=>s.CopyNextOfflineProgrammingRequest());Closed(()=>s.Interrupt());
  // Missing, duplicate and malformed owned exchanges cannot open programming.
  foreach(string bad in new[]{"R 6cf0186800","T 6c18f02701","T 6cfef028","R 6cf0187f2822"})
  {var f=New();Check(Observe(f,bad)==AL5SpsSavedFrameDisposition.Rejected);Check(f.Phase==AL5SpsOfflinePhase.Stopped);Closed(()=>Observe(f,setup[0]));}
  var duplicate=New();Observe(duplicate,setup[0]);Observe(duplicate,setup[1]);Check(Observe(duplicate,setup[1])==AL5SpsSavedFrameDisposition.Rejected);
  var shortSeed=New();for(int i=0;i<3;i++)Observe(shortSeed,setup[i]);Check(Observe(shortSeed,"R 6cf018670137")==AL5SpsSavedFrameDisposition.Rejected);
  var badKey=New();for(int i=0;i<5;i++)Observe(badKey,setup[i]);Check(Observe(badKey,"R 6cf018670235")==AL5SpsSavedFrameDisposition.Rejected);
  var early=New();Check(early.ObserveSavedFrame(true,plan.CopyRequest(0))==AL5SpsSavedFrameDisposition.Rejected);
  var foreign=New();for(int i=0;i<11;i++)Observe(foreign,setup[i]);Check(Observe(foreign,"R 6cf060e0aa")==AL5SpsSavedFrameDisposition.Unrelated);Check(Observe(foreign,setup[12])==AL5SpsSavedFrameDisposition.Rejected);
  var waiting=New();Setup(waiting);waiting.ObserveSavedFrame(true,plan.CopyRequest(0));Check(Observe(waiting,"R 6cf0187f3622")==AL5SpsSavedFrameDisposition.Rejected);
  // Every cleanup boundary remains interruptible, with no implicit restart or identity write.
  for(int stop=0;stop<cleanup.Length;stop++)
  {
   var f=New();Setup(f);Program(f,plan);for(int i=0;i<stop;i++)Observe(f,cleanup[i]);f.Interrupt();
   Check(f.Phase==AL5SpsOfflinePhase.Stopped);Closed(()=>Observe(f,cleanup[stop]));
  }
  foreach(string wrong in new[]{"R 6cf0187f2822","T 6c18f02701","T 6c18f036","R 6cf018760086"})
  {var f=New();Setup(f);Program(f,plan);Check(Observe(f,wrong)==AL5SpsSavedFrameDisposition.Rejected);Check(f.Phase==AL5SpsOfflinePhase.Stopped);}
  var ordinaryInsteadOfShort=New();Setup(ordinaryInsteadOfShort);Program(ordinaryInsteadOfShort,plan);for(int i=0;i<3;i++)Observe(ordinaryInsteadOfShort,cleanup[i]);Check(Observe(ordinaryInsteadOfShort,"R 6cf01867011234")==AL5SpsSavedFrameDisposition.Rejected);
  var oversize=New();Check(oversize.ObserveSavedFrame(false,new byte[4109])==AL5SpsSavedFrameDisposition.Rejected);
  foreach(int stage in new[]{0,1,2})
  {var f=New();if(stage>0)Setup(f);if(stage>1)Program(f,plan);f.Interrupt();Check(f.Phase==AL5SpsOfflinePhase.Stopped);}
  var vin=New();Setup(vin);Program(vin,plan);Check(Observe(vin,"T 6c18f03b01004141414141")==AL5SpsSavedFrameDisposition.Rejected);
  Console.WriteLine("Offline lifecycle setup, cleanup, interruption, ownership and excluded-identity tests passed.");
  if(corpus!=null)
  {
   var actual=New();int consumed=0;var lines=File.ReadAllLines(corpus);
   foreach(var line in lines)
   {
    var disposition=Observe(actual,line);Check(disposition!=AL5SpsSavedFrameDisposition.Rejected);consumed++;
    if(actual.Phase==AL5SpsOfflinePhase.CompletedObservations)break;
   }
   Check(actual.Phase==AL5SpsOfflinePhase.CompletedObservations && actual.AcknowledgedBlocks==180 && actual.PendingReplies==201);
   Check(actual.SetupObservations==15 && actual.CleanupObservations==10 && consumed<lines.Length);
   Console.WriteLine($"Saved lifecycle passed: {consumed} records, {actual.SetupObservations} setup, {actual.CleanupObservations} cleanup, {actual.KeepAlives} keepalives, {actual.UnrelatedReplies} unrelated replies; {lines.Length-consumed} trailing records excluded.");
  }
 }
}

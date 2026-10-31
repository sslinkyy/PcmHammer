using System;
using System.IO;
using PcmHacking;
class Program
{
 static void Check(bool x){if(!x)throw new Exception("Coverage assertion failed");}
 static void Reject(Action a){try{a();}catch(ArgumentException){return;}catch(InvalidOperationException){return;}throw new Exception("Expected rejection");}
 static byte[] Data(int a)=>new byte[]{(byte)a,(byte)(a+1),(byte)(a+2),(byte)(a+3)};
 static byte[] Reply(int a)=>new byte[]{0x6C,0xF0,0x18,0x63,(byte)(a>>8),(byte)a,1,2,3,4};
 static void Main(string[] args)
 {
  Reject(()=>new AL5SpsSavedFlashCoverage(new byte[679828]));
  foreach(int a in new[]{-1,0x3FD5,0x3FD8,0xC4C64,0xC4C66,0xFFFFD,int.MaxValue})Check(!AL5SpsSavedFlashCoverage.PermissionAllowsDword(a));
  if(args.Length!=1)throw new ArgumentException("Pinned expanded SPS OS path required; read-only input.");
  var firmware=File.ReadAllBytes(args[0]);
  var campaign=new AL5SpsSavedReadCampaign(firmware);campaign.BeginSavedRequest(0x8000);Reject(()=>campaign.StartLogicalSegment());
  Check(campaign.ObserveSavedReply(Reply(0x8004),out _,out _)==AL5SavedReplyKind.Unrelated && campaign.HasPendingRequest);
  Check(campaign.ObserveSavedReply(Reply(0x8000),out var accepted,out _)==AL5SavedReplyKind.MatchingLow16Echo);
  campaign.StartLogicalSegment();Reject(()=>campaign.BeginSavedRequest(0x18000));Check(campaign.Stopped && campaign.MatchedDwords==1);
  // Native event tracing shows that an acknowledged body can be requeued verbatim.
  // Neither an observed positive reply nor a logical segment may authorize its echo again.
  var retainedReply=Reply(0x8000);var requeued=new AL5SpsSavedReadCampaign(firmware);
  requeued.BeginSavedRequest(0x8000);requeued.ObserveSavedReply(retainedReply,out _,out _);
  Reject(()=>requeued.ObserveSavedReply(retainedReply,out _,out _));requeued.StartLogicalSegment();
  Reject(()=>requeued.BeginSavedRequest(0x18000));Check(requeued.Stopped);
  var otherEcho=new AL5SpsSavedReadCampaign(firmware);otherEcho.BeginSavedRequest(0x8000);otherEcho.ObserveSavedReply(retainedReply,out _,out _);
  otherEcho.StartLogicalSegment();otherEcho.BeginSavedRequest(0x18004);
  Check(otherEcho.ObserveSavedReply(retainedReply,out _,out _)==AL5SavedReplyKind.Unrelated && otherEcho.HasPendingRequest);
  otherEcho.ObserveSavedReply(Reply(0x18004),out _,out _);Check(otherEcho.MatchedDwords==2 && !otherEcho.PhysicalBoundaryProven);
  var timed=new AL5SpsSavedReadCampaign(firmware);timed.BeginSavedRequest(0xC5F94);timed.TimeoutOrCancel();Reject(()=>timed.StartLogicalSegment());Reject(()=>timed.ObserveSavedReply(Reply(0xC5F94),out _,out _));
  var unknownHistory=new AL5SpsSavedReadCampaign(firmware);unknownHistory.BeginSavedRequest(0x18000);Check(unknownHistory.ObserveSavedReply(Reply(0x8000),out _,out _)==AL5SavedReplyKind.MatchingLow16Echo);Check(!unknownHistory.FreshnessProven && !unknownHistory.FullAddressIdentityProven);
  var overlap=new AL5SpsSavedReadCampaign(firmware);overlap.BeginSavedRequest(0xC4C62);Check(overlap.ObserveSavedReply(Reply(0xC4C62),out _,out _)==AL5SavedReplyKind.MatchingLow16Echo);
  foreach(var m in new[]{new byte[]{0x6C,0xF0,0x18,0x7F,0x23,0x31},new byte[]{0x6C,0xF0,0x18,0x63}}){var n=new AL5SpsSavedReadCampaign(firmware);n.BeginSavedRequest(0x4000);n.ObserveSavedReply(m,out _,out _);Check(n.Stopped);}
  var x=new AL5SpsSavedFlashCoverage(firmware);Reject(()=>x.CopyKnownRange(0,4));
  var owned=Data(0x8000);x.ObserveSavedDword(0x8000,owned);owned[0]^=1;Check(x.CopyKnownRange(0x8000,4)[0]==0);
  Reject(()=>x.ObserveSavedDword(0x7FFE,new byte[]{1,2,3,4}));Check(x.UnknownBytesInRange(0x7FFE,2)==2);
  foreach(int a in new[]{0x3FD8,0xC4C64})Reject(()=>x.ObserveSavedDword(a,Data(a)));
  for(int a=0;a<0x100000;a+=4)if(AL5SpsSavedFlashCoverage.PermissionAllowsDword(a))x.ObserveSavedDword(a,Data(a));
  Check(x.UnknownByteCount==8);Check(x.ObserveSavedDword(0xC4C62,Data(0xC4C62)));Check(x.UnknownByteCount==6);
  Check(x.UnknownBytesInRange(0,0x4000)==4 && x.UnknownBytesInRange(0x4000,0x4000)==0);
  Check(x.UnknownBytesInRange(0x15FD8,41000)==0 && x.UnknownBytesInRange(0xC5F94,237676)==0);
  Check(!x.ObserveSavedDword(0xC4C62,Data(0xC4C62)));Reject(()=>x.CopyKnownRange(0,0x100000));
  Check(!x.FullImageAvailable && !x.ExtendedLiveReadEnabled && !x.FullAddressIdentityProven && !x.FreshnessProven && !x.LiveWriteEnabled);
  Console.WriteLine("PASS synthetic full-flash coverage retains six permission-excluded bytes, overlap conflict atomicity, ownership and blocked freshness/read/write flags.");
 }
}
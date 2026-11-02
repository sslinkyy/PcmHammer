using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using PcmHacking;

static class ReadOnlyCollateralCampaignTest
{
 static byte[] Nonce()=>Convert.FromHexString("0123456789ABCDEF");
 static void Check(bool b){if(!b)throw new Exception("Collateral campaign assertion failed");}
 static void Reject(Action action){try{action();}catch(ArgumentException){return;}catch(InvalidOperationException){return;}throw new Exception("Expected campaign rejection");}
 static byte[] Reply(byte[] request,Func<uint,byte> value)
 {
  var frame=new byte[26+request[23]];frame[0]=0x6D;frame[1]=0xF0;frame[2]=0x18;frame[3]=0xF1;
  var payload=new byte[22+request[23]];Array.Copy(request,4,payload,0,20);payload[0]=0x61;payload[1]=0x72;payload[3]=0;
  uint address=((uint)request[20]<<16)|((uint)request[21]<<8)|request[22];
  for(int i=0;i<request[23];i++)payload[20+i]=value(address+(uint)i);
  AL5ReadOnlyCoreSession.SetCrc(payload);Array.Copy(payload,0,frame,4,payload.Length);return frame;
 }
 static void CheckClosed(AL5ReadOnlyCollateralCampaign s)
 {Reject(()=>s.BeginNextSavedVpwRequest());Reject(()=>s.TimeoutOrCancel());Reject(()=>s.ObserveSavedVpwReply(new byte[4]));}
 static void Synthetic(ushort marker)
 {
  var s=new AL5ReadOnlyCollateralCampaign(Nonce());Reject(()=>s.CopySavedSupplement());Reject(()=>s.CopySavedCollateral());
  byte[]? previous=null;int frames=0;
  while(!s.Complete)
  {
   var req=s.BeginNextSavedVpwRequest();Reject(()=>s.BeginNextSavedVpwRequest());
   uint address=((uint)req[20]<<16)|((uint)req[21]<<8)|req[22];
   Check(address==0x15FD8+s.BytesObserved && req[23]==Math.Min(32,41000-s.BytesObserved));
   int before=s.BytesObserved;
   if(previous!=null)Check(s.ObserveSavedVpwReply(previous)==AL5ReadOnlyCoreReply.Unrelated && s.BytesObserved==before && s.HasPendingRequest);
   var reply=Reply(req,a=>a==0x1FFFE?(byte)(marker>>8):a==0x1FFFF?(byte)marker:(byte)(a^0x5A));
   Check(s.ObserveSavedVpwReply(reply)==AL5ReadOnlyCoreReply.Matched);previous=reply;frames++;
  }
  Check(frames==1282 && s.BytesObserved==41000 && s.MatchedReplies==1282 && s.SavedCompletionMarker==marker);
  Check(s.CopySavedCollateral().Length==40998 && s.CopySavedSupplement().Length==41000);
  var detached=s.CopySavedSupplement();detached[0]^=1;Check(detached[0]!=s.CopySavedSupplement()[0]);
  var snapshot=s.AssembleSavedSnapshot(new byte[57304]);Check(snapshot.Length==98304 && snapshot[^2]==(byte)(marker>>8) && snapshot[^1]==(byte)marker);
  Reject(()=>s.AssembleSavedSnapshot(new byte[57303]));
  Check(!s.LiveUploadEnabled && !s.LiveExecutionEnabled && !s.LiveWriteEnabled && !s.HardwareQualified && !s.PhysicalReadbackVerified && !s.IndependentCollateralBackupVerified);
  CheckClosed(s);
 }
 static void Failures()
 {
  var s=new AL5ReadOnlyCollateralCampaign(Nonce());var req=s.BeginNextSavedVpwRequest();var valid=Reply(req,_=>0x4A);
  s.ObserveSavedVpwReply(valid);s.BeginNextSavedVpwRequest();s.TimeoutOrCancel();Check(s.Stopped && s.BytesObserved==32 && !s.Complete && s.SavedCompletionMarker==null);Reject(()=>s.CopySavedSupplement());CheckClosed(s);
  var fresh=new AL5ReadOnlyCollateralCampaign(Convert.FromHexString("1123456789ABCDEF"));fresh.BeginNextSavedVpwRequest();Check(fresh.ObserveSavedVpwReply(valid)==AL5ReadOnlyCoreReply.Unrelated && fresh.BytesObserved==0);
  var bad=new AL5ReadOnlyCollateralCampaign(Nonce());var pending=bad.BeginNextSavedVpwRequest();var corrupt=Reply(pending,_=>1);corrupt[^1]^=1;
  Check(bad.ObserveSavedVpwReply(corrupt)==AL5ReadOnlyCoreReply.Malformed && bad.Stopped && bad.BytesObserved==0);Reject(()=>bad.CopySavedCollateral());CheckClosed(bad);
  // A missing/corrupt final eight-byte reply must not manufacture the marker.
  var late=new AL5ReadOnlyCollateralCampaign(Nonce());
  while(late.BytesObserved<40992){var r=late.BeginNextSavedVpwRequest();Check(late.ObserveSavedVpwReply(Reply(r,_=>0x4A))==AL5ReadOnlyCoreReply.Matched);}
  var end=late.BeginNextSavedVpwRequest();Check(end[23]==8);var broken=Reply(end,_=>0xFC);broken[^1]^=1;
  Check(late.ObserveSavedVpwReply(broken)==AL5ReadOnlyCoreReply.Malformed && late.BytesObserved==40992 && !late.Complete && late.SavedCompletionMarker==null);
  Reject(()=>late.CopySavedSupplement());Reject(()=>late.CopySavedCollateral());CheckClosed(late);
 }
 static void Main(string[] args)
 {
  Synthetic(0x4AFC);Synthetic(0x1234);Failures();
  Console.WriteLine("PASS complete 41,000-byte synthetic campaigns, marker retention, stale-session/reply rejection, interruption and disabled hardware gates.");
  if(args.Length==1)
  {
   using var doc=JsonDocument.Parse(File.ReadAllText(args[0]));var root=doc.RootElement;
   Check(root.GetProperty("schema").GetString()=="al5-offline-compiled-collateral-campaign-v1" && root.GetProperty("persistent_cpu_ram_session").GetBoolean());
   var s=new AL5ReadOnlyCollateralCampaign(Nonce());byte[]? previous=null;
   foreach(var row in root.GetProperty("frames").EnumerateArray())
   {
    Check(Convert.ToHexString(s.BeginNextSavedVpwRequest()).ToLowerInvariant()==row.GetProperty("vpw_request_hex").GetString());
    int before=s.BytesObserved;
    if(previous!=null)Check(s.ObserveSavedVpwReply(previous)==AL5ReadOnlyCoreReply.Unrelated && before==s.BytesObserved);
    previous=Convert.FromHexString(row.GetProperty("vpw_reply_hex").GetString()!);Check(s.ObserveSavedVpwReply(previous)==AL5ReadOnlyCoreReply.Matched);
   }
   Check(s.Complete && s.MatchedReplies==1282 && s.SavedCompletionMarker==Convert.ToUInt16(root.GetProperty("marker_hex").GetString(),16));
   var data=s.CopySavedSupplement();Check(Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant()==root.GetProperty("supplement_sha256").GetString());
   for(int i=0;i<data.Length;i++){int a=0x15FD8+i;Check(data[i]==(byte)(a*17+(a>>16)));}
   Console.WriteLine($"PASS all {s.MatchedReplies} compiled-kernel replies through production host campaign: {data.Length} exact bytes; marker {s.SavedCompletionMarker:X4}.");
  }
 }
}

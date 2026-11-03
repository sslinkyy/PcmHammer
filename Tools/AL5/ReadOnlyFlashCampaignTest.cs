using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using PcmHacking;

static class ReadOnlyFlashCampaignTest
{
 static byte[] Nonce()=>Convert.FromHexString("0123456789ABCDEF");
 static void Check(bool value){if(!value)throw new Exception("Full-flash campaign assertion failed");}
 static void Reject(Action action){try{action();}catch(ArgumentException){return;}catch(InvalidOperationException){return;}throw new Exception("Expected campaign rejection");}
 static string Hash(byte[] b)=>Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();
 static void Recrc(byte[] frame){var payload=frame.Skip(4).ToArray();AL5ReadOnlyCoreSession.SetCrc(payload);Array.Copy(payload,0,frame,4,payload.Length);}
 static byte[] Reply(byte[] request,byte[] flash)
 {
  int count=request[23],address=(request[20]<<16)|(request[21]<<8)|request[22];
  var payload=new byte[22+count];Array.Copy(request,4,payload,0,20);payload[0]=0x61;payload[1]=0x72;payload[3]=0;
  Array.Copy(flash,address,payload,20,count);AL5ReadOnlyCoreSession.SetCrc(payload);
  var frame=new byte[4+payload.Length];new byte[]{0x6D,0xF0,0x18,0xF1}.CopyTo(frame,0);payload.CopyTo(frame,4);return frame;
 }
 static void Blocked(AL5ReadOnlyFlashCampaign c)=>Check(!c.LiveUploadEnabled && !c.LiveExecutionEnabled && !c.LiveWriteEnabled && !c.ReadyToFlash && !c.PhysicalReadbackVerified && !c.PhysicalAddressMappingVerified && !c.RecoveryVerified);
 static void Main(string[] args)
 {
  Reject(()=>new AL5ReadOnlyFlashCampaign(new byte[8]));Reject(()=>new AL5ReadOnlyFlashCampaign(new byte[7]));
  var synthetic=Enumerable.Range(0,0x100000).Select(a=>(byte)(a^(a>>8)^(a>>16))).ToArray();
  var campaign=new AL5ReadOnlyFlashCampaign(Nonce());Reject(()=>campaign.CopySavedImage());
  byte[]? previous=null;
  for(int address=0;address<synthetic.Length;address+=32)
  {
   var request=campaign.BeginNextSavedVpwRequest();Reject(()=>campaign.BeginNextSavedVpwRequest());
   Check(((request[20]<<16)|(request[21]<<8)|request[22])==address && request[23]==32);
   if(previous!=null){int n=campaign.BytesObserved;Check(campaign.ObserveSavedVpwReply(previous)==AL5ReadOnlyCoreReply.Unrelated && campaign.BytesObserved==n);}
   var response=Reply(request,synthetic);
   if(address%0x10000==0)
   {
    var wrongBank=(byte[])response.Clone();wrongBank[20]^=1;Recrc(wrongBank);
    Check(campaign.ObserveSavedVpwReply(wrongBank)==AL5ReadOnlyCoreReply.Unrelated && campaign.HasPendingRequest);
    var oldNonce=(byte[])response.Clone();oldNonce[8]^=1;Recrc(oldNonce);
    Check(campaign.ObserveSavedVpwReply(oldNonce)==AL5ReadOnlyCoreReply.Unrelated && campaign.HasPendingRequest);
   }
   Check(campaign.ObserveSavedVpwReply(response)==AL5ReadOnlyCoreReply.Matched);
   Reject(()=>campaign.ObserveSavedVpwReply(response));previous=response;
  }
  Check(campaign.Complete && campaign.UnknownByteCount==0 && campaign.MatchedReplies==32768 && campaign.CopySavedImage().SequenceEqual(synthetic));
  var copy=campaign.CopySavedImage();copy[0]^=1;Check(campaign.CopySavedImage()[0]!=copy[0]);
  Reject(()=>campaign.BeginNextSavedVpwRequest());Reject(()=>campaign.TimeoutOrCancel());Blocked(campaign);
  foreach(bool malformed in new[]{false,true})
  {
   var c=new AL5ReadOnlyFlashCampaign(Nonce());var request=c.BeginNextSavedVpwRequest();
   if(malformed){var response=Reply(request,synthetic);response[^1]^=1;Check(c.ObserveSavedVpwReply(response)==AL5ReadOnlyCoreReply.Malformed);}
   else c.TimeoutOrCancel();
   Check(c.Stopped && c.BytesObserved==0 && c.UnknownByteCount==0x100000);Reject(()=>c.CopySavedImage());Reject(()=>c.BeginNextSavedVpwRequest());Blocked(c);
  }
  Console.WriteLine("PASS full synthetic 1 MiB campaign: all banks, nonce/address/sequence correlation, closed-state rejection and no invented incomplete image.");
  if(args.Length==0)return;
  if(args.Length!=3)throw new ArgumentException("Use full-campaign directory and pinned LOW/HIGH paths.");
  byte[] low=File.ReadAllBytes(args[1]),high=File.ReadAllBytes(args[2]);
  Check(low.Length==0x20000 && Hash(low)=="cf5dd139e52ba5925fc95f166627a9a7abcac1374ded8cb738df8297b961a3f6");
  Check(high.Length==0xE0000 && Hash(high)=="492040d9460d53b77dda606b9a89f4254e0680f239093001663f6ed5cf51ba75");
  byte[] expected=low.Concat(high).ToArray();using var doc=JsonDocument.Parse(File.ReadAllText(Path.Combine(args[0],"result.json")));var root=doc.RootElement;
  string origin=root.TryGetProperty("fixture_origin",out var originValue)?originValue.GetString()!:"historical_flash";
  if(origin=="atomic_post_preparation")
  {
   var fixture=File.ReadAllBytes(Path.Combine(args[0],"fixture.offline.bin"));Check(fixture.Length==0x100000);
   int differences=0;
   for(int i=0;i<fixture.Length;i++)if(i<0x4000 || i>=0x8000)Check(fixture[i]==expected[i]);else if(fixture[i]!=expected[i])differences++;
   var preparation=root.GetProperty("preparation_context");Check(preparation.GetProperty("stop_pc").GetString()=="0xbe78c" && preparation.GetProperty("marker").GetString()=="0xbfc1");
   Check(Hash(expected.Skip(0x4000).Take(0x4000).ToArray())==preparation.GetProperty("pre_banks_sha256").GetString());
   Check(Hash(fixture.Skip(0x4000).Take(0x4000).ToArray())==preparation.GetProperty("post_banks_sha256").GetString());
   Check(differences==preparation.GetProperty("bank_differences").GetProperty("0x4000").GetInt32()+preparation.GetProperty("bank_differences").GetProperty("0x6000").GetInt32());
   Check(root.GetProperty("native_reset_context").GetProperty("initial_ram_sha256").GetString()==preparation.GetProperty("ram_sha256").GetString());
   expected=fixture;
  }
  else Check(origin=="historical_flash");
  foreach(var dependency in root.GetProperty("dependency_sha256").EnumerateObject())
   Check(Hash(File.ReadAllBytes(Path.Combine(args[0],"source_snapshot",dependency.Name)))==dependency.Value.GetString());
  Check(root.GetProperty("complete").GetBoolean() && root.GetProperty("request_count").GetInt32()==32768 && root.GetProperty("bytes").GetInt32()==0x100000 && root.GetProperty("flash_sha256").GetString()==Hash(expected));
  foreach(string flag in new[]{"physical_readback_verified","physical_address_mapping_verified","recovery_verified","live_upload_enabled","live_execution_enabled","live_write_enabled","ready_to_flash"})Check(!root.GetProperty(flag).GetBoolean());
  var actual=new AL5ReadOnlyFlashCampaign(Nonce());int count=0;
  foreach(string line in File.ReadLines(Path.Combine(args[0],"frames.jsonl")))
  {
   using var row=JsonDocument.Parse(line);var r=row.RootElement;
   Check(r.GetProperty("address").GetInt32()==actual.BytesObserved && r.GetProperty("count").GetInt32()==32);
   Check(Convert.ToHexString(actual.BeginNextSavedVpwRequest()).ToLowerInvariant()==r.GetProperty("vpw_request_hex").GetString());
   Check(actual.ObserveSavedVpwReply(Convert.FromHexString(r.GetProperty("vpw_reply_hex").GetString()!))==AL5ReadOnlyCoreReply.Matched);count++;
  }
  Check(count==32768 && actual.Complete && actual.CopySavedImage().SequenceEqual(expected) && Hash(actual.CopySavedImage())==root.GetProperty("readback_sha256").GetString());
  Check(File.ReadAllBytes(Path.Combine(args[0],"readback.offline.bin")).SequenceEqual(expected));Blocked(actual);
  Console.WriteLine($"PASS 32768 compiled-kernel replies through production full-flash host campaign: all 1048576 fixture bytes exact ({origin}); physical gates closed.");
 }
}

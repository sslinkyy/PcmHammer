using System;
using System.IO;
using System.Collections.Generic;
using System.Text.Json;
using PcmHacking;
static class Al5SecurityAuditTest
{
 static void Check(bool b){if(!b)throw new Exception("Security audit assertion failed");}
 static AL5SavedSecuritySeed Parse(string hex)=>AL5SavedSecuritySeed.Parse(Convert.FromHexString(hex));
 static void Main(string[] args)
 {
  foreach(string seed in new[]{"0000","0001","37FF","9CE5","FFFF"})
  {var s=Parse("6cf0186701"+seed);Check(s.Kind==AL5SavedSeedKind.Seed && s.Seed==Convert.ToUInt16(seed,16));Check(!s.SecurityAuthorizationProven && !s.GeneralFreshSeedSupportVerified && !s.LiveSecuritySubmissionEnabled);}
  Check(Parse("6cf018670137").Kind==AL5SavedSeedKind.Short37Unqualified);
  foreach(string bad in new[]{"6cf0186701","6cf018670100","6cf01867019ce500"})Check(Parse(bad).Kind==AL5SavedSeedKind.Malformed);
  foreach(string other in new[]{"6cf01067019ce5","6cf018670234","6df01867019ce5"})Check(Parse(other).Kind==AL5SavedSeedKind.Unrelated);
  Check(KeyAlgorithm.GetKey(50,0x9CE5)==0xBC08);
  Console.WriteLine("PASS strict AL5 seed parsing: short 37 never authorizes, full 37xx remains a seed, malformed tails rejected.");
  if(args.Length>0)
  {
   using var doc=JsonDocument.Parse(File.ReadAllText(args[0]));var root=doc.RootElement;
   Check(root.GetProperty("sps_handler_matches_pinned_code").GetBoolean() && !root.GetProperty("general_fresh_seed_support_verified").GetBoolean());
   var native=root.GetProperty("native_authorization");Check(native.GetProperty("all_pass").GetBoolean() && native.GetProperty("saved_security_selector").GetInt32()==0);
   int comparisons=0,differences=0;
   foreach(var row in root.GetProperty("native_selector_one_samples").EnumerateArray())
   {ushort seed=(ushort)row.GetProperty("seed").GetInt32();int actual=row.GetProperty("native_selector_one_key").GetInt32();if(KeyAlgorithm.GetKey(50,seed)!=actual)differences++;comparisons++;if(seed==0x9CE5)Check(actual==0xACE1);}
   Check(differences>0);int pairs=0,shortReplies=0;
   for(int i=1;i<args.Length;i++)
   {
    ushort? pending=null;
    foreach(var line in File.ReadLines(args[i]))
    {
     var bytes=Convert.FromHexString(line.Substring(2));
     if(line[0]=='R')
     {var s=AL5SavedSecuritySeed.Parse(bytes);if(s.Kind==AL5SavedSeedKind.Seed)pending=s.Seed;if(s.Kind==AL5SavedSeedKind.Short37Unqualified){pending=null;shortReplies++;}}
     if(line.StartsWith("T 6c18f02702",StringComparison.Ordinal))
     {Check(bytes.Length==7 && pending.HasValue);ushort key=(ushort)((bytes[5]<<8)|bytes[6]);Check(pending==0x9CE5 && key==0xBC08 && KeyAlgorithm.GetKey(50,pending.Value)==key);pairs++;pending=null;}
    }
   }
   Check(pairs>0 && shortReplies>0);
   Console.WriteLine($"PASS native security audit: {native.GetProperty("cases").GetArrayLength()} cases, {comparisons} isolated transform samples ({differences} differ from algorithm 50), {pairs} captured fixed-pair exchanges and {shortReplies} short-37 observations. Fresh generic unlock remains unqualified.");
  }
 }
}

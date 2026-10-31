using System;
using System.IO;
using PcmHacking;
class Program
{
 static void Check(bool x){if(!x)throw new Exception("Coverage assertion failed");}
 static void Reject(Action a){try{a();}catch(ArgumentException){return;}catch(InvalidOperationException){return;}throw new Exception("Expected rejection");}
 static byte[] Data(int a)=>new byte[]{(byte)a,(byte)(a+1),(byte)(a+2),(byte)(a+3)};
 static void Main(string[] args)
 {
  Reject(()=>new AL5SpsSavedFlashCoverage(new byte[679828]));
  foreach(int a in new[]{-1,0x3FD5,0x3FD8,0xC4C64,0xC4C66,0xFFFFD,int.MaxValue})Check(!AL5SpsSavedFlashCoverage.PermissionAllowsDword(a));
  if(args.Length!=1)throw new ArgumentException("Pinned expanded SPS OS path required; read-only input.");
  var x=new AL5SpsSavedFlashCoverage(File.ReadAllBytes(args[0]));Reject(()=>x.CopyKnownRange(0,4));
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
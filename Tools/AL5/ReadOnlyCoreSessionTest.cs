using System;
using System.IO;
using System.Text;
using System.Text.Json;
using PcmHacking;
class Program
{
 static byte[] Nonce()=>Convert.FromHexString("0123456789ABCDEF");
 static void Check(bool x){if(!x)throw new Exception("Protocol assertion failed");}
 static void Reject(Action a){try{a();}catch(ArgumentException){return;}catch(InvalidOperationException){return;}throw new Exception("Expected rejection");}
 static byte[] Reply(byte[] r){var p=new byte[22+r[19]];Array.Copy(r,p,20);p[0]=0x61;p[1]=0x72;p[3]=0;for(int i=0;i<r[19];i++)p[20+i]=(byte)i;AL5ReadOnlyCoreSession.SetCrc(p);return p;}
 static void Main(string[] args)
 {
  Check(AL5ReadOnlyCoreSession.Crc(Encoding.ASCII.GetBytes("123456789"),9)==0x29B1);
  Reject(()=>new AL5ReadOnlyCoreSession(new byte[8]));
  var n=Nonce();var s=new AL5ReadOnlyCoreSession(n);n[0]^=1;
  Reject(()=>s.BeginSavedRead(0xFFFFF,2));var request=s.BeginSavedRead(0x8000,4);Check(request[4]==1);Reject(()=>s.BeginSavedRead(0x18000,4));
  var first=Reply(request);Check(s.ObserveSavedReply(first,out var data)==AL5ReadOnlyCoreReply.Matched && data.Length==4);Reject(()=>s.ObserveSavedReply(first,out _));
  var next=s.BeginSavedRead(0x18000,4);Check(s.ObserveSavedReply(first,out _)==AL5ReadOnlyCoreReply.Unrelated && s.HasPendingRequest);
  var bankWrong=Reply(next);bankWrong[16]^=1;AL5ReadOnlyCoreSession.SetCrc(bankWrong);Check(s.ObserveSavedReply(bankWrong,out _)==AL5ReadOnlyCoreReply.Unrelated);
  var nonceWrong=Reply(next);nonceWrong[4]^=1;AL5ReadOnlyCoreSession.SetCrc(nonceWrong);Check(s.ObserveSavedReply(nonceWrong,out _)==AL5ReadOnlyCoreReply.Unrelated);
  var countWrong=Reply(next);countWrong[19]=3;Check(s.ObserveSavedReply(countWrong,out _)==AL5ReadOnlyCoreReply.Malformed && s.Stopped);
  var envelope=new AL5ReadOnlyCoreSession(Nonce());envelope.BeginSavedVpwRead(0x8000,4);
  Check(envelope.ObserveSavedVpwReply(Convert.FromHexString("6cf018f1"),out _)==AL5ReadOnlyCoreReply.Unrelated && envelope.HasPendingRequest);
  Check(envelope.ObserveSavedVpwReply(Convert.FromHexString("6df018f1"),out _)==AL5ReadOnlyCoreReply.Malformed && envelope.Stopped);
  var timed=new AL5ReadOnlyCoreSession(Nonce());timed.BeginSavedRead(0,1);timed.TimeoutOrCancel();Reject(()=>timed.BeginSavedRead(0,1));
  var fresh=new AL5ReadOnlyCoreSession(Convert.FromHexString("1123456789ABCDEF"));fresh.BeginSavedRead(0x8000,4);Check(fresh.ObserveSavedReply(first,out _)==AL5ReadOnlyCoreReply.Unrelated);
  Check(!fresh.LiveUploadEnabled && !fresh.LiveExecutionEnabled && !fresh.HardwareQualified && !fresh.LiveWriteEnabled);
  if(args.Length==1){using var j=JsonDocument.Parse(File.ReadAllText(args[0]));int matched=0;foreach(var c in j.RootElement.GetProperty("valid_cases").EnumerateArray()){
   var host=new AL5ReadOnlyCoreSession(Nonce());var r=host.BeginSavedRead(c.GetProperty("address").GetUInt32(),c.GetProperty("count").GetInt32());
   Check(Convert.ToHexString(r).ToLowerInvariant()==c.GetProperty("request_hex").GetString());
   var wire=Convert.FromHexString(c.GetProperty("reply_hex").GetString()!);Check(host.ObserveSavedReply(wire,out var bytes)==AL5ReadOnlyCoreReply.Matched);
   for(int i=0;i<bytes.Length;i++)Check(bytes[i]==wire[20+i]);
   if(c.TryGetProperty("vpw_request_hex",out var vf)){
    var framed=new AL5ReadOnlyCoreSession(Nonce());Check(Convert.ToHexString(framed.BeginSavedVpwRead(c.GetProperty("address").GetUInt32(),c.GetProperty("count").GetInt32())).ToLowerInvariant()==vf.GetString());
    Check(framed.ObserveSavedVpwReply(Convert.FromHexString(c.GetProperty("vpw_reply_hex").GetString()!),out var frameData)==AL5ReadOnlyCoreReply.Matched && Convert.ToHexString(frameData)==Convert.ToHexString(bytes));
   }matched++;
  }Console.WriteLine("PASS "+matched+" actual compiled M68K reply vectors and identical host request vectors.");
   if(j.RootElement.TryGetProperty("session_transcript",out var transcript)){
    var session=new AL5ReadOnlyCoreSession(Nonce());byte[]? previous=null;int frames=0;
    foreach(var c in transcript.EnumerateArray()){
     var req=session.BeginSavedRead(c.GetProperty("address").GetUInt32(),c.GetProperty("count").GetInt32());
     Check(Convert.ToHexString(req).ToLowerInvariant()==c.GetProperty("request_hex").GetString());
     if(previous!=null)Check(session.ObserveSavedReply(previous,out _)==AL5ReadOnlyCoreReply.Unrelated && session.HasPendingRequest);
     previous=Convert.FromHexString(c.GetProperty("reply_hex").GetString()!);Check(session.ObserveSavedReply(previous,out _)==AL5ReadOnlyCoreReply.Matched);frames++;
    }Console.WriteLine("PASS "+frames+" persistent compiled-runtime bank transitions with delayed-reply rejection.");
   }
  }
  Console.WriteLine("PASS offline nonce/sequence/full-address/count/CRC correlation, rejection and disabled hardware gates.");
 }
}
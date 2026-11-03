using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using PcmHacking;

static class PersistentBankCampaignTest
{
    static void Check(bool value) { if (!value) throw new Exception("Persistent bank assertion failed"); }
    static void Reject(Action action)
    {
        try { action(); } catch (ArgumentException) { return; } catch (InvalidOperationException) { return; }
        throw new Exception("Expected rejection");
    }
    static byte[] Reply(int address, byte[] data) => new byte[] {
        0x6C,0xF0,0x18,0x63,(byte)(address>>8),(byte)address }.Concat(data).ToArray();
    static void Blocked(AL5SavedPersistentBankCampaign c) => Check(!c.PreEntryAcquisitionProven &&
        !c.FreshnessProven && !c.FullAddressIdentityProven && !c.LiveReadEnabled &&
        !c.LiveUploadEnabled && !c.LiveExecutionEnabled && !c.LiveWriteEnabled && !c.ReadyToFlash);
    static void Main(string[] args)
    {
        if(args.Length < 1 || args.Length > 2) throw new ArgumentException("Supply pinned saved SPS OS and optionally native rehearsal directory; no adapter is used.");
        var firmware = File.ReadAllBytes(args[0]);
        Reject(() => new AL5SavedPersistentBankCampaign(new byte[679828]));
        var c = new AL5SavedPersistentBankCampaign(firmware);
        Reject(() => c.CopyCompleteSavedBanks());
        Reject(() => c.ObserveSavedVpwReply(Reply(0x4000,new byte[4]),out _));
        var expected = Enumerable.Range(0,0x4000).Select(i => (byte)(i^(i>>7)^0xA7)).ToArray();
        for(int offset=0;offset<expected.Length;offset+=4)
        {
            int address=0x4000+offset;
            Check(c.BeginNextSavedVpwRequest().SequenceEqual(new byte[]{0x6D,0x18,0xF0,0x23,0,(byte)(address>>8),(byte)address,1}));
            Reject(() => c.BeginNextSavedVpwRequest());
            Check(c.ObserveSavedVpwReply(Reply(address+4,new byte[4]),out _)==AL5SavedReplyKind.Unrelated);
            Check(c.HasPendingRequest && c.BytesObserved==offset);
            var response=Reply(address,expected.Skip(offset).Take(4).ToArray());
            Check(c.ObserveSavedVpwReply(response,out _)==AL5SavedReplyKind.MatchingLow16Echo);
            response[6]^=1;
            if(!c.Complete) Reject(() => c.ObserveSavedVpwReply(response,out _));
        }
        Check(c.Complete && c.UnknownByteCount==0 && c.CopyCompleteSavedBanks().SequenceEqual(expected));
        var copy=c.CopyCompleteSavedBanks();copy[0]^=1;Check(c.CopyCompleteSavedBanks()[0]==expected[0]);
        Reject(() => c.BeginNextSavedVpwRequest());Reject(() => c.TimeoutOrCancel());Blocked(c);
        foreach(var failure in new[]{"timeout","negative","malformed"})
        {
            c=new AL5SavedPersistentBankCampaign(firmware);c.BeginNextSavedVpwRequest();
            if(failure=="timeout")c.TimeoutOrCancel();
            else c.ObserveSavedVpwReply(failure=="negative" ? new byte[]{0x6C,0xF0,0x18,0x7F,0x23,0x31} : new byte[]{0x6C,0xF0,0x18,0x63},out _);
            Check(c.Stopped && c.UnknownByteCount==0x4000);Reject(() => c.CopyCompleteSavedBanks());
            Reject(() => c.BeginNextSavedVpwRequest());Blocked(c);
        }
        // An old same-echo reply is intrinsically indistinguishable on this wire format.
        // Preserve the limitation instead of claiming that our bounded plan fixes freshness.
        c=new AL5SavedPersistentBankCampaign(firmware);c.BeginNextSavedVpwRequest();
        Check(c.ObserveSavedVpwReply(Reply(0x14000,new byte[]{1,2,3,4}),out _)==AL5SavedReplyKind.MatchingLow16Echo);
        Blocked(c);
        Console.WriteLine("PASS 4096 bounded saved bank exchanges, ownership, stop/incomplete guards; same-echo ambiguity explicitly remains unqualified.");
        if(args.Length==2)
        {
            c=new AL5SavedPersistentBankCampaign(firmware);
            foreach(string line in File.ReadLines(Path.Combine(args[1],"frames.jsonl")))
            {
                using var row=JsonDocument.Parse(line);var root=row.RootElement;
                Check(root.GetProperty("address").GetInt32()==0x4000+c.BytesObserved);
                Check(c.BeginNextSavedVpwRequest().SequenceEqual(Convert.FromHexString(root.GetProperty("vpw_request_hex").GetString()!)));
                Check(c.ObserveSavedVpwReply(Convert.FromHexString(root.GetProperty("vpw_reply_hex").GetString()!),out _)==AL5SavedReplyKind.MatchingLow16Echo);
            }
            Check(c.CopyCompleteSavedBanks().SequenceEqual(File.ReadAllBytes(Path.Combine(args[1],"fixture.offline.bin"))));Blocked(c);
            Console.WriteLine("PASS native resident-handler transcript through production saved-bank campaign: 16384 synthetic bytes exact.");
        }
    }
}

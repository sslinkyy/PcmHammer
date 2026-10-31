using System;
using PcmHacking;

internal static class SavedReadSessionTest
{
    static void Check(bool value) { if (!value) throw new Exception("Saved read correlation assertion failed"); }
    static void Reject(Action action)
    {
        try { action(); } catch (InvalidOperationException) { return; }
        throw new Exception("Ambiguous transaction accepted");
    }
    static byte[] Reply(int address) => new byte[] {0x6C,0xF0,0x18,0x63,(byte)(address>>8),(byte)address,1,2,3,4};
    public static void Run()
    {
        var session=new AL5SavedReadSession();
        Reject(()=>session.Observe(Reply(0x8000),out _,out _));
        session.Begin(0x8000);
        Reject(()=>session.Begin(0x8004));
        Check(session.Observe(Reply(0x8004),out _,out _)==AL5SavedReplyKind.Unrelated && session.HasPendingRequest);
        Check(session.Observe(Reply(0x8000),out _,out _)==AL5SavedReplyKind.MatchingLow16Echo);
        Reject(()=>session.Observe(Reply(0x8000),out _,out _));
        session.Begin(0x8004);
        Check(session.Observe(Reply(0x8000),out _,out _)==AL5SavedReplyKind.Unrelated);
        session.Observe(Reply(0x8004),out _,out _);
        Reject(()=>session.Begin(0x18000));
        Check(session.Stopped && session.MatchedDwords==2 && !session.FreshnessProven);
        var timedOut=new AL5SavedReadSession();timedOut.Begin(0x15FD8);timedOut.TimeoutOrCancel();
        Reject(()=>timedOut.Observe(Reply(0x15FD8),out _,out _));
        Reject(()=>timedOut.Begin(0x15FD8));
        foreach (var bytes in new[]{Convert.FromHexString("6cf0187f2331"),Convert.FromHexString("6cf01863")})
        {
            var bad=new AL5SavedReadSession();bad.Begin(0x15FD8);bad.Observe(bytes,out _,out _);
            Check(bad.Stopped && bad.MatchedDwords==0);
        }
        var supplement=new AL5SavedReadSession();
        for(int a=0x15FD8;a<=0x1FFFC;a+=4)
        {
            supplement.Begin(a);
            Check(supplement.Observe(Reply(a),out _,out _)==AL5SavedReplyKind.MatchingLow16Echo);
        }
        Check(supplement.MatchedDwords==10250 && !supplement.Stopped && !supplement.LiveReadEnabled);
        // A response from outside this instance can still alias: explicitly never prove freshness.
        var unknownHistory=new AL5SavedReadSession();unknownHistory.Begin(0x18000);
        Check(unknownHistory.Observe(Reply(0x8000),out _,out _)==AL5SavedReplyKind.MatchingLow16Echo && !unknownHistory.FreshnessProven);
        Console.WriteLine("PASS offline stale/duplicate, timeout, negative, echo-reuse and 10250-dword correlation checks");
    }
}

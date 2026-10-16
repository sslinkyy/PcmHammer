// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Threading;
using PcmHacking;

// A null vehicle deliberately makes any accidental transport access fail.
internal sealed class GateLogger : ILogger
{
    public int Rejections;
    public int InvalidAssessments;
    public int SnapshotRequiredAssessments;
    public void AddUserMessage(string message)
    {
        if (message.Contains("AL5 calibration-segment writing is disabled")) Rejections++;
        if (message.Contains("AL5 offline retry assessment: InvalidCandidate.")) InvalidAssessments++;
        if (message.Contains("AL5 offline retry assessment: SnapshotRequired.")) SnapshotRequiredAssessments++;
    }
    public void AddDebugMessage(string message) { }
    public void StatusUpdateActivity(string value) { }
    public void StatusUpdateTimeRemaining(string value) { }
    public void StatusUpdatePercentDone(string value) { }
    public void StatusUpdateRetryCount(string value) { }
    public void StatusUpdateProgressBar(double value, bool visible) { }
    public void StatusUpdateKbps(string value) { }
    public void StatusUpdateReset() { }
}

internal static class GateTest
{
    public static int Main()
    {
        var logger = new GateLogger();
        int calls = 0;
        byte[] valid = new byte[AL5CalibrationReader.Length];
        Put(valid, 0x8024, new byte[] { 0x00, 0xE7, 0xB0, 0x58 });
        Put(valid, 0xA996, new byte[] { 0x11, 0xF7, 0x0C, 0x68, 0x07, 0x3E, 0x05, 0xA0, 0x04, 0x00, 0x02, 0xD9 });
        Put(valid, 0x158A8, new byte[] { 0x00, 0x11, 0x00, 0x09 });
        Put(valid, 0x15FD4, new byte[] { 0x50, 0x7C, 0xCC, 0x15 }); // Independent Python golden.
        foreach (byte[] image in new[] { new byte[AL5CalibrationReader.Length], valid })
        foreach (WriteType writeType in Enum.GetValues(typeof(WriteType)))
        foreach (PcmType pcmType in Enum.GetValues(typeof(PcmType)))
        {
            var writer = new WriteManager(logger, null, writeType, null, null, CancellationToken.None);
            bool success = writer.Write(image, pcmType).GetAwaiter().GetResult();
            if (success) throw new Exception("AL5 writing unexpectedly enabled");
            calls++;
        }
        if (logger.Rejections != calls) throw new Exception("Missing explicit AL5 rejection");
        if (logger.InvalidAssessments != calls/2 || logger.SnapshotRequiredAssessments != calls/2)
            throw new Exception("WriteManager did not consume the offline workflow assessment");
        Console.WriteLine("AL5 gate rejected " + calls + " write-type/forced-controller combinations before vehicle access.");
        return 0;
    }

    private static void Put(byte[] image, int address, byte[] bytes)
    { Array.Copy(bytes, 0, image, address - AL5CalibrationReader.StartAddress, bytes.Length); }
}

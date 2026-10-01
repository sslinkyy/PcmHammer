// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Threading;
using PcmHacking;

// A null vehicle deliberately makes any accidental transport access fail.
internal sealed class GateLogger : ILogger
{
    public int Rejections;
    public void AddUserMessage(string message)
    {
        if (message.Contains("AL5 calibration-segment writing is disabled")) Rejections++;
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
        foreach (WriteType writeType in Enum.GetValues(typeof(WriteType)))
        foreach (PcmType pcmType in Enum.GetValues(typeof(PcmType)))
        {
            var writer = new WriteManager(logger, null, writeType, null, null, CancellationToken.None);
            bool success = writer.Write(new byte[AL5CalibrationReader.Length], pcmType).GetAwaiter().GetResult();
            if (success) throw new Exception("AL5 writing unexpectedly enabled");
            calls++;
        }
        if (logger.Rejections != calls) throw new Exception("Missing explicit AL5 rejection");
        Console.WriteLine("AL5 gate rejected " + calls + " write-type/forced-controller combinations before vehicle access.");
        return 0;
    }
}

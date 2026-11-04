using PcmHacking;
using System.Security.Cryptography;
using System.Text.Json;

static partial class Program
{
    static AL5CalibrationWriteCandidate RehearseSavedPreparedCandidate(byte[] baseline,byte[] prepared)
    {
        byte[] calibration=baseline.AsSpan(0x8000,AL5CalibrationInspection.Length).ToArray();
        var sectors=new AL5CalibrationSectorPlan(calibration,baseline.AsSpan(0x8000,AL5ProgrammingWorkflow.SnapshotLength).ToArray());
        var plan=new AL5EfiOfflineWritePlan(loader,AL5CalibrationWriteCandidate.LoaderSha256,calibration,sectors.CopyCollateralBackup());
        var candidate=new AL5CalibrationWriteCandidate(loader,calibration,baseline);bool recorded=false;
        foreach(string line in lines)
        {
            bool tx=line[0]=='T';byte[] frame=Convert.FromHexString(line.Substring(2));
            if(!recorded && candidate.State==AL5CapturedWriteState.EraseRequest){candidate.RecordSavedPreparedBanks(prepared);recorded=true;}
            if(tx && frame.Length>12 && frame[3]==0x36 && frame[4]==0)
            {int address=(frame[7]<<16)|(frame[8]<<8)|frame[9];frame=plan.CopyRequest(2+(address-0x8000)/512);}
            candidate.ObserveSavedFrame(tx,frame);
        }
        Check(recorded && candidate.State==AL5CapturedWriteState.AwaitingSavedVerification,"Full scripted cleanup precedes saved verification");return candidate;
    }

    static void PostResetVerificationCases(string reportPath,byte[] baseline)
    {
        using var document=JsonDocument.Parse(File.ReadAllBytes(reportPath));var report=document.RootElement;
        string Hash(byte[] data)=>Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
        Check(report.GetProperty("schema").GetString()=="al5-watchdog-inheritance-post-reset-v1" && report.GetProperty("reference_sha256").GetString()==Hash(baseline),"Post-reset trace owns the exact selected reference");
        foreach(string flag in new[]{"hardware_access","physical_watchdog_configuration_verified","physical_reset_verified","independent_readback_verified","host_verification_window_proven","live_upload_enabled","live_execution_enabled","live_write_enabled","ready_to_flash"})
            Check(!report.GetProperty(flag).GetBoolean(),"Native check results cannot promote physical authority");
        var rows=report.GetProperty("cases").EnumerateArray().ToDictionary(row=>row.GetProperty("case").GetString()!);
        var expected=new Dictionary<string,string>{["watchdog_retained"]="post_reset_calibration_check_return",["calibration_crc_corrupt"]="post_reset_calibration_crc_rejected",
            ["calibration_compensation_corrupt"]="post_reset_calibration_check_return",["calibration_marker_missing"]="post_reset_calibration_marker_rejected"};
        foreach(var pair in expected)
        {
            byte[] readback=(byte[])baseline.Clone();
            if(pair.Key=="calibration_crc_corrupt")readback[0x8100]^=1;
            if(pair.Key=="calibration_compensation_corrupt")readback[0x15FD7]^=1;
            if(pair.Key=="calibration_marker_missing"){readback[0x1FFFE]=255;readback[0x1FFFF]=255;}
            var observed=rows[pair.Key].GetProperty("observed");
            Check(observed.GetProperty("flash_fixture_sha256").GetString()==Hash(readback) && observed.GetProperty("stop").GetString()==pair.Value,"Actual native outcome binds to these saved bytes");
            var candidate=RehearseSavedPreparedCandidate(baseline,baseline.AsSpan(0x4000,0x4000).ToArray());
            var assessment=candidate.VerifySavedFullReadback(readback);bool equal=pair.Key=="watchdog_retained";
            Check(candidate.CompleteSavedComparison==equal && assessment.ExactSavedImageMatch==equal,"Native application acceptance cannot replace complete independent-file comparison");
            if(!equal)Check(candidate.State==AL5CapturedWriteState.Stopped,"Any changed CRC, compensation or completion marker stops the saved writer");
            Check(!candidate.PhysicalReadbackVerified && !candidate.ReadyToFlash && !candidate.LiveWriteEnabled,"A matching saved control is still not physical qualification");
            results.Add(new {name="post_reset_native_check_does_not_replace_full_verification",fixture=pair.Key,native_stop=pair.Value,strict_saved_match=equal,passed=true});
        }
    }
}

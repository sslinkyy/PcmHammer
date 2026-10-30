// SPDX-License-Identifier: GPL-3.0-only
// Offline prefix fixture comes from the same hash-pinned independent GT image.
using System;
using System.Linq;
using System.Security.Cryptography;
using PcmHacking;

internal static partial class AutoCalKernelProbePolicyTest
{
    private const string ShortRequest = "6D10F035010040000000";
    private static AutoCalKernelProbePolicy ShortDataReady()
    {
        var p = new AutoCalKernelProbePolicy(kernel, shortRead: true);
        Tx(p, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434444E");
        Tx(p, "6C10F02701"); Rx(p, "6CF01067010000");
        p.BeforeTransmit(p.UploadPermissionMessage); Rx(p, "6CF010740044");
        p.BeforeTransmit(p.UploadMessages[0]); Rx(p, "6CF010760078");
        p.BeforeTransmit(p.UploadMessages[1]); Rx(p, "6CF010768078");
        Tx(p, "6C10F03D00"); Rx(p, "6CF0107D006AB178EC36");
        Tx(p, "6C10F03D01"); Rx(p, "6CF0107D0100894471");
        return p;
    }
    private static byte[] ShortReply()
    {
        byte[] reply = new Protocol().CreateBlockMessage(baseline.Value, 0, 64, 0, BlockCopyType.Copy).GetBytes();
        reply[1] = 0xF0; reply[2] = 0x10; reply[4] = 1;
        return VpwUtilities.AddBlockChecksum(reply);
    }
    private static void ShortReadSuccess()
    {
        Require(Convert.ToHexString(SHA256.HashData(baseline.Value.Take(64).ToArray())).ToLowerInvariant() ==
            AutoCalKernelProbePolicy.ExpectedShortReadSha256, "short SHA derived from pinned independent complete baseline");
        Require(Convert.ToHexString(new Protocol().CreateReadRequest(0, 64).GetBytes()) == ShortRequest,
            "fixed64-byte addresszero wire request");
        var p = ShortDataReady();
        Require(p.ShortReadEnabled && p.ReadEnabled && !p.FullReadEnabled && p.ReadImage.Length == 64,
            "short mode and buffer extent explicit");
        Tx(p, ShortRequest); p.ObserveReceive(ShortReply());
        Require(p.IsShortReadVerified && p.ReadBlockAttempts == 1 && p.ReadBlockReplies == 1,
            "one exact prefix reply qualified");
        Require(!p.IsImageReadComplete && !p.IsImageVerified && !p.BaselineShaMatched && p.VerifiedCrcRanges == 0 && p.CrcQueryAttempts == 0,
            "prefix never represented as complete image or controller CRC verification");
        Require(p.ComputedImageSha256 == AutoCalKernelProbePolicy.ExpectedShortReadSha256 && p.ReadImage.SequenceEqual(baseline.Value.Take(64)),
            "exact prefix content and digest retained");
        p.ReadImage[0] ^= 1; Require(p.ReadImage.SequenceEqual(baseline.Value.Take(64)), "prefix snapshot defensive");
        Tx(p, "6C10F020"); Rx(p, "6CF01060"); Tx(p, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434444E");
        Require(p.IsPostExitIdentityVerified, "short verified experiment can restore ordinary identity");
    }
    private static void ShortReadRequests()
    {
        bool rejected = false;
        try { new AutoCalKernelProbePolicy(kernel, fullRead: true, shortRead: true); }
        catch (ArgumentException) { rejected = true; }
        Require(rejected, "conflicting read modes refused before I/O");
        foreach (byte[] request in new[] { DataRequest(0), new Protocol().CreateReadRequest(64, 64).GetBytes(),
            new Protocol().CreateReadRequest(0, 63).GetBytes(), Hex("6C10F03D02000040000000"), Hex("6C10F020"), Hex("6C10F03D05000000") })
        { var p = ShortDataReady(); Reject(() => p.BeforeTransmit(request), "different size/address CRC earlyexit or erase"); }
        var pending = ShortDataReady(); Tx(pending, ShortRequest);
        Reject(() => Tx(pending, ShortRequest), "uncertain short read cannot replay");
        foreach (byte[] request in new[] { Hex(ShortRequest), new Protocol().CreateReadRequest(64, 64).GetBytes(), Hex("6C10F03D02000040000000") })
        { var p = ShortDataReady(); Tx(p, ShortRequest); p.ObserveReceive(ShortReply()); Reject(() => p.BeforeTransmit(request), "successful prefix does not admit another read or CRC"); }
        Require(ShortDataReady().ToolPresentAttemptLimit == 32, "short experiment retains bounded startup notification limit");
    }
    private static void ShortReadResponses()
    {
        foreach (int extent in new[] { 10, 75, 77, 4108 })
        {
            var p = ShortDataReady(); Tx(p, ShortRequest); byte[] bad = new byte[extent];
            Array.Copy(ShortReply(), bad, Math.Min(extent, 76));
            Reject(() => p.ObserveReceive(bad), "wrong exact extent " + extent);
            Require(!p.IsShortReadVerified && p.ReadBlockReplies == 0, "invalid extent adds no coverage");
        }
        foreach (int field in new[] { 4, 5, 6, 7, 8, 9 })
        { var p = ShortDataReady(); Tx(p, ShortRequest); byte[] bad = ShortReply(); bad[field] ^= 1; VpwUtilities.AddBlockChecksum(bad);
          Reject(() => p.ObserveReceive(bad), "checksum-valid wrong short header " + field); }
        var sum = ShortDataReady(); Tx(sum, ShortRequest); byte[] corrupt = ShortReply(); corrupt[10] ^= 1;
        Reject(() => sum.ObserveReceive(corrupt), "short block checksum corruption");
        var changed = ShortDataReady(); Tx(changed, ShortRequest); VpwUtilities.AddBlockChecksum(corrupt);
        Reject(() => changed.ObserveReceive(corrupt), "valid checksum but wrong baseline prefix");
        Require(changed.ReadBlockReplies == 1 && !changed.IsShortReadVerified && !changed.IsImageVerified && changed.ComputedImageSha256 != null,
            "received prefix coverage retained independently from failed equality");
        Reject(() => Tx(changed, "6C10F020"), "failed prefix does not authorize exit");
        var negative = ShortDataReady(); Tx(negative, ShortRequest); Reject(() => Rx(negative, "6CF0107F3531"), "negative read reply");
    }
    private static void ShortReadHostBoundary()
    {
        var p = new AutoCalKernelProbePolicy(kernel, shortRead: true); var g = HostReady(p);
        HostTx(p, g, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434");
        HostTx(p, g, "6C10F02701"); Rx(p, "6CF01067010000");
        HostTx(p, g, p.UploadPermissionMessage); Rx(p, "6CF010740044");
        HostTx(p, g, p.UploadMessages[0]); Rx(p, "6CF010760078");
        HostTx(p, g, p.UploadMessages[1]); Rx(p, "6CF010768078");
        HostTx(p, g, "6C10F03D00"); Rx(p, "6CF0107D006AB178EC36");
        HostTx(p, g, "6C10F03D01"); Rx(p, "6CF0107D0100894471");
        HostTx(p, g, ShortRequest);
        Reject(() => HostFinish(g, new ProbeProfile(true).Requests[5]), "no host cleanup before prefix arrives");
        p.ObserveReceive(ShortReply());
        HostTx(p, g, "6C10F020"); Rx(p, "6CF01060"); HostTx(p, g, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434");
        foreach (byte[] frame in new ProbeProfile(true).Requests.Skip(5)) HostFinish(g, frame);
        Require(p.IsShortReadVerified && p.IsPostExitIdentityVerified && !p.IsImageVerified && g.VpwPayloadCommandsCompleted == 10,
            "host native guard admits only fixed10-command zero-seed prefix sequence and successful cleanup");
    }
}

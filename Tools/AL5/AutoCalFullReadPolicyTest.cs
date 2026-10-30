// SPDX-License-Identifier: GPL-3.0-only
// File-only fixtures from the already saved GT baseline; no hardware transport.
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using PcmHacking;

internal static partial class AutoCalKernelProbePolicyTest
{
    private static readonly Lazy<byte[]> baseline = new(() =>
    {
        byte[] bytes = File.ReadAllBytes(AutoCalKernelProbePolicy.DefaultBaselinePath);
        if (bytes.Length != AutoCalKernelProbePolicy.FullReadLength ||
            Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant() != AutoCalKernelProbePolicy.ExpectedBaselineSha256)
            throw new InvalidDataException("Full-read test baseline pin mismatch.");
        return bytes;
    });
    private static readonly string[] savedCrcReplies = {
        "6CF0107D02020000060000D6703728", "6CF0107D0202000004000057DBDAAF",
        "6CF0107D020200000200004E3F92B0", "6CF0107D02018000008000712EFE11",
        "6CF0107D0200200000600085B5BB36", "6CF0107D020020000040007D830D3E",
        "6CF0107D02004000000000CED58D53" };
    private static AutoCalKernelProbePolicy FullVersion(bool acknowledged = false)
    {
        var p = new AutoCalKernelProbePolicy(kernel, fullRead: true, useZeroSubmodeKernel: acknowledged, prependReadAcknowledgement: acknowledged, acknowledgedFullRead: acknowledged);
        Tx(p, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434444E");
        Tx(p, "6C10F02701"); Rx(p, "6CF01067010000");
        p.BeforeTransmit(p.UploadPermissionMessage); Rx(p, "6CF010740044");
        p.BeforeTransmit(p.UploadMessages[0]); Rx(p, "6CF010760078");
        p.BeforeTransmit(p.UploadMessages[1]); Rx(p, "6CF010768078");
        Tx(p, "6C10F03D00"); Rx(p, "6CF0107D006AB178EC36");
        return p;
    }
    private static AutoCalKernelProbePolicy FullDataReady()
    {
        var p = FullVersion(); Tx(p, "6C10F03D01"); Rx(p, "6CF0107D0100894471"); return p;
    }
    private static byte[] DataRequest(int index) => new Protocol().CreateReadRequest(index * 4096, 4096).GetBytes();
    private static byte[] DataReply(int index)
    {
        byte[] reply = new Protocol().CreateBlockMessage(baseline.Value, index * 4096, 4096, index * 4096, BlockCopyType.Copy).GetBytes();
        reply[1] = 0xF0; reply[2] = 0x10; reply[4] = 1;
        return VpwUtilities.AddBlockChecksum(reply);
    }
    private static AutoCalKernelProbePolicy FullCrcReady()
    {
        var p = FullDataReady();
        for (int index = 0; index < 128; index++) { p.BeforeTransmit(DataRequest(index)); p.ObserveReceive(DataReply(index)); }
        return p;
    }
    private static void AcknowledgedFullReadOffline()
    {
        var p = FullVersion(true); Tx(p, "6C10F03D01"); Rx(p, "6CF0107D0100894471");
        for (int index = 0; index < 128; index++)
        {
            p.BeforeTransmit(DataRequest(index)); Rx(p, "6DF010750154");
            byte[] reply = DataReply(index); reply[4] = 0; VpwUtilities.AddBlockChecksum(reply);
            p.ObserveReceive(reply);
            Require(p.ReadAcknowledgementCount == index + 1 && p.ReadBlockReplies == index + 1,
                "one acknowledgement required for each sequential block");
        }
        Require(p.BaselineShaMatched && !p.IsImageVerified, "full baseline needs controller CRCs");
        for (int index = 0; index < 7; index++) { p.BeforeTransmit(p.CrcRequests[index]); Rx(p, savedCrcReplies[index]); }
        Require(p.IsImageVerified && p.VerifiedCrcRanges == 7, "all CRC ranges verified offline");
        Tx(p, "6C10F020"); Rx(p, "6CF01060"); Tx(p, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434444E");
        Require(p.IsPostExitIdentityVerified, "explicit exit follows full verification");
        var missing = FullVersion(true); Tx(missing, "6C10F03D01"); Rx(missing, "6CF0107D0100894471");
        missing.BeforeTransmit(DataRequest(0)); Rx(missing, "6DF010750154");
        byte[] first = DataReply(0); first[4] = 0; VpwUtilities.AddBlockChecksum(first); missing.ObserveReceive(first);
        missing.BeforeTransmit(DataRequest(1));
        byte[] second = DataReply(1); second[4] = 0; VpwUtilities.AddBlockChecksum(second);
        Reject(() => missing.ObserveReceive(second), "previous block ACK cannot authorize next block");
        Require(missing.ReadBlockReplies == 1, "missing second ACK adds no coverage");
    }

    private static void FullReadSourcePins()
    {
        Require(baseline.Value.Length == 524288, "512KiB SHA-pinned actual GT baseline");
        string directory = Path.GetDirectoryName(AutoCalKernelProbePolicy.DefaultBaselinePath)!;
        string log = Path.GetFullPath(Path.Combine(directory, "..", "e54_gt_actual_write_01", "after_flash_read.log"));
        Require(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(log))).ToLowerInvariant() ==
            "81ee71f8fa907ff7795397491d7ab9d05485aece755e5c21b371b3afb0855216", "actual read log pin");
        const string prefix = "[DEBUG] Received: ";
        byte[][] responses = File.ReadLines(log).Where(line => line.StartsWith(prefix))
            .Select(line => Hex(line[prefix.Length..].Replace(" ", ""))).ToArray();
        Require(responses.Any(r => r.SequenceEqual(DataReply(0))) && responses.Any(r => r.SequenceEqual(DataReply(127))),
            "generated boundary blocks equal actual independent GT receive frames");
        Require(savedCrcReplies.All(hex => responses.Any(r => r.SequenceEqual(Hex(hex)))), "seven exact CRC replies exist in source log");
        // The known-chip factory path has no logger side effects.
        var info = FlashChip.Create(0x00894471, null!);
        var p = FullVersion();
        Require(p.CrcRequests.Select(Convert.ToHexString).SequenceEqual(info.MemoryRanges.Select(r =>
            Convert.ToHexString(new Protocol().CreateCrcQuery(r.Address, r.Size).GetBytes()))), "pinned CRC ranges equal production Intel flash layout");
        Require(p.FullReadEnabled && p.IsKernelVerified && !p.IsImageReadComplete && !p.IsImageVerified,
            "running kernel does not imply image qualification");
    }
    private static void FullReadSuccess()
    {
        var p = FullCrcReady();
        Require(p.ReadBlockAttempts == 128 && p.ReadBlockReplies == 128 && p.IsImageReadComplete,
            "exact128block transfer coverage");
        Require(p.BaselineShaMatched && p.ComputedImageSha256 == AutoCalKernelProbePolicy.ExpectedBaselineSha256,
            "full image hash matches independent baseline");
        Require(p.ReadImage.SequenceEqual(baseline.Value) && !p.IsImageVerified, "read bytes retained; controller CRC still required");
        p.ReadImage[0] ^= 1; Require(p.ReadImage.SequenceEqual(baseline.Value), "image snapshot is defensive");
        for (int index = 0; index < 7; index++) { p.BeforeTransmit(p.CrcRequests[index]); Rx(p, savedCrcReplies[index]); }
        Require(p.VerifiedCrcRanges == 7 && p.CrcQueryAttempts == 7 && p.IsImageVerified, "all seven controller CRCs verified");
        Tx(p, "6C10F020"); Rx(p, "6CF01060"); Tx(p, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434444E");
        Require(p.IsPostExitIdentityVerified && p.Failure == null, "restoration only after complete validated image");
    }
    private static void FullReadRequestRestrictions()
    {
        foreach (byte[] bad in new[] { DataRequest(1), new Protocol().CreateReadRequest(0, 2048).GetBytes(),
            new Protocol().CreateReadRequest(0x80000, 4096).GetBytes(), new Protocol().CreateReadRequest(0xFF9100, 4096).GetBytes(),
            Hex("6C10F03D05008000"), Hex("6C10F020"), Hex("6CFEF0A1"), Hex("8CFEF014"), Hex("6C10F03D02004000000000") })
        { var p = FullDataReady(); Reject(() => p.BeforeTransmit(bad), "off-plan or premature full-read command"); }
        var wrongFlash = FullVersion(); Tx(wrongFlash, "6C10F03D01");
        Reject(() => Rx(wrongFlash, "6CF0107D01000122AB"), "different flash chip cannot change read layout");
        var duplicate = FullDataReady(); duplicate.BeforeTransmit(DataRequest(0));
        Reject(() => duplicate.BeforeTransmit(DataRequest(0)), "no duplicate data request while waiting");
        var stale = FullDataReady(); stale.BeforeTransmit(DataRequest(0)); stale.ObserveReceive(DataReply(0));
        Reject(() => stale.BeforeTransmit(DataRequest(0)), "completed data block cannot repeat");
        var defaultPolicy = Verified(); Reject(() => Tx(defaultPolicy, "6C10F03D01"), "kernel-only mode does not silently gain fullread");
    }
    private static void FullReadMalformedResponses()
    {
        foreach (int field in new[] { 4, 5, 6, 7, 8, 9 })
        {
            var p = FullDataReady(); p.BeforeTransmit(DataRequest(0)); byte[] bad = DataReply(0); bad[field] ^= 1;
            VpwUtilities.AddBlockChecksum(bad);
            Reject(() => p.ObserveReceive(bad), "valid-checksum wrong submode/length/address" + field);
            Require(p.ReadBlockReplies == 0 && !p.IsImageReadComplete, "malformed block adds no coverage");
        }
        foreach (int extent in new[] { 10, 4107, 4109 })
        {
            var p = FullDataReady(); p.BeforeTransmit(DataRequest(0)); byte[] bad = new byte[extent];
            Array.Copy(DataReply(0), bad, Math.Min(extent, 4108));
            Reject(() => p.ObserveReceive(bad), "strict received extent" + extent);
        }
        var sum = FullDataReady(); sum.BeforeTransmit(DataRequest(0)); byte[] corrupt = DataReply(0); corrupt[100] ^= 1;
        Reject(() => sum.ObserveReceive(corrupt), "invalid block checksum");
        Require(sum.LastReceive!.SequenceEqual(corrupt), "rejected raw block preserved");
        var negative = FullDataReady(); negative.BeforeTransmit(DataRequest(0));
        Reject(() => Rx(negative, "6CF0107F3531"), "negative read reply");
        var unrelated = FullDataReady(); unrelated.BeforeTransmit(DataRequest(0)); byte[] other = DataReply(0); other[2] = 0x18;
        unrelated.ObserveReceive(other); Require(unrelated.ReadBlockReplies == 0, "different controller adds no coverage");
        unrelated.ObserveReceive(DataReply(0)); Require(unrelated.ReadBlockReplies == 1, "valid response can follow retained unrelated frame");
    }
    private static void FullReadBaselineMismatch()
    {
        var p = FullDataReady();
        for (int index = 0; index < 127; index++) { p.BeforeTransmit(DataRequest(index)); p.ObserveReceive(DataReply(index)); }
        p.BeforeTransmit(DataRequest(127)); byte[] changed = DataReply(127); changed[10] ^= 1; VpwUtilities.AddBlockChecksum(changed);
        Reject(() => p.ObserveReceive(changed), "checksum-valid changed image cannot pass pinned SHA");
        Require(p.IsImageReadComplete && !p.BaselineShaMatched && !p.IsImageVerified && p.ComputedImageSha256 != null,
            "completed coverage and failed baseline identity remain distinct");
        Reject(() => p.BeforeTransmit(p.CrcRequests[0]), "failed image cannot advance to CRC");
        Reject(() => Tx(p, "6C10F020"), "failed read does not silently perform restoration");
    }
    private static void FullReadCrcFailures()
    {
        foreach (int field in new[] { 4, 5, 8, 10, 11, 14 })
        {
            var p = FullCrcReady(); p.BeforeTransmit(p.CrcRequests[0]); byte[] bad = Hex(savedCrcReplies[0]); bad[field] ^= 1;
            Reject(() => p.ObserveReceive(bad), "CRC wrong submode/range/value" + field);
            Require(p.VerifiedCrcRanges == 0 && !p.IsImageVerified, "invalid CRC adds no verified ranges");
        }
        foreach (string bad in new[] { savedCrcReplies[0][..^2], savedCrcReplies[0] + "00", "6CF0107F3D0278" })
        { var p = FullCrcReady(); p.BeforeTransmit(p.CrcRequests[0]); Reject(() => Rx(p, bad), "CRC extent or unqualified pending-negative reply"); }
        var wrongOrder = FullCrcReady(); Reject(() => wrongOrder.BeforeTransmit(wrongOrder.CrcRequests[1]), "CRC order is fixed");
        var duplicate = FullCrcReady(); duplicate.BeforeTransmit(duplicate.CrcRequests[0]); Rx(duplicate, savedCrcReplies[0]);
        Reject(() => duplicate.BeforeTransmit(duplicate.CrcRequests[0]), "completed CRC range cannot repeat");
    }
    private static void FullReadBudgets()
    {
        var p = FullCrcReady();
        for (int i = 0; i < AutoCalKernelProbePolicy.MaximumCrcQueriesPerRange; i++) p.BeforeTransmit(p.CrcRequests[0]);
        Require(p.CrcQueryAttempts == 6 && p.VerifiedCrcRanges == 0, "bounded same-range read-only polling");
        Rx(p, savedCrcReplies[0]); Require(p.VerifiedCrcRanges == 1, "eventual exact CRC reply advances range once");
        for (int i = 0; i < 6; i++) p.BeforeTransmit(p.CrcRequests[1]);
        Reject(() => p.BeforeTransmit(p.CrcRequests[1]), "seventh pending CRC poll blocked");
        var notify = FullDataReady();
        Require(notify.ToolPresentAttemptLimit == 211, "notification bound derived from data and CRC budgets");
        for (int i = 0; i < notify.ToolPresentAttemptLimit; i++) Tx(notify, "8CFEF03F");
        Reject(() => Tx(notify, "8CFEF03F"), "fullread notification budget enforced");
    }
    private static void FullReadHostBoundary()
    {
        var p = new AutoCalKernelProbePolicy(kernel, true); var g = HostReady(p);
        HostTx(p, g, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434");
        HostTx(p, g, "6C10F02701"); Rx(p, "6CF01067010000");
        HostTx(p, g, p.UploadPermissionMessage); Rx(p, "6CF010740044");
        HostTx(p, g, p.UploadMessages[0]); Rx(p, "6CF010760078");
        HostTx(p, g, p.UploadMessages[1]); Rx(p, "6CF010768078");
        HostTx(p, g, "6C10F03D00"); Rx(p, "6CF0107D006AB178EC36");
        Reject(() => HostFinish(g, new ProbeProfile(true).Requests[5]), "no cleanup after version alone in fullread mode");
        HostTx(p, g, "6C10F03D01"); Rx(p, "6CF0107D0100894471");
        for (int i = 0; i < 128; i++) { HostTx(p, g, DataRequest(i)); p.ObserveReceive(DataReply(i)); }
        for (int i = 0; i < 7; i++) { HostTx(p, g, p.CrcRequests[i]); Rx(p, savedCrcReplies[i]); }
        HostTx(p, g, "6C10F020"); Rx(p, "6CF01060"); HostTx(p, g, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434");
        foreach (byte[] frame in new ProbeProfile(true).Requests.Skip(5)) HostFinish(g, frame);
        Require(p.IsImageVerified && p.IsPostExitIdentityVerified && g.VpwPayloadCommandsCompleted == 144,
            "host boundary includes128reads sevenCRC and fixed guarded session only");
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// In-memory, one-data-byte experiment. No kernel file is written or executed.
using System;
using System.Linq;
using System.Security.Cryptography;
using PcmHacking;

internal static partial class AutoCalKernelProbePolicyTest
{
    private static void ZeroSubmodePin()
    {
        byte[] original = (byte[])kernel.Clone();
        var ordinary = new AutoCalKernelProbePolicy(kernel, shortRead: true);
        var variant = new AutoCalKernelProbePolicy(kernel, shortRead: true, useZeroSubmodeKernel: true);
        Require(kernel.SequenceEqual(original), "derivation does not mutate the caller's original asset");
        Require(!ordinary.UsesZeroSubmodeKernel && ordinary.ReadReplySubmode == 1 &&
            ordinary.EffectiveKernelSha256 == AutoCalKernelProbePolicy.ExpectedKernelSha256,
            "default preserves the original exact asset and response submode");
        byte[] effective = variant.KernelBytes;
        int[] changes = Enumerable.Range(0, kernel.Length).Where(i => kernel[i] != effective[i]).ToArray();
        Require(changes.SequenceEqual(new[] { 0x7AE }) && original[0x7AE] == 1 && effective[0x7AE] == 0,
            "only pinned response-template data byte changes");
        Require(effective.AsSpan(0x7AA, 10).SequenceEqual(Hex("6DF01036000000000000")),
            "effective template retains all address length and routing defaults");
        Require(variant.UsesZeroSubmodeKernel && variant.ReadReplySubmode == 0 &&
            variant.EffectiveKernelSha256 == AutoCalKernelProbePolicy.ExpectedZeroSubmodeKernelSha256 &&
            Convert.ToHexString(SHA256.HashData(effective)).ToLowerInvariant() ==
                "17a351715bbdd366cf77e33ad5d0b801fa0747f2d31c57478ad3bb409ee58fe3",
            "derived bytes match independent one-byte digest");
        effective[0] ^= 1;
        Require(variant.KernelBytes[0] == original[0], "effective asset getter returns a defensive clone");
        byte[] caller = (byte[])kernel.Clone();
        var owned = new AutoCalKernelProbePolicy(caller, shortRead: true, useZeroSubmodeKernel: true);
        caller[0x7AE] = 0x55;
        Require(owned.KernelBytes[0x7AE] == 0 && owned.EffectiveKernelSha256 == variant.EffectiveKernelSha256,
            "caller mutation cannot change the effective kernel");
    }

    private static AutoCalKernelProbePolicy ZeroCopyReady()
    {
        var p = new AutoCalKernelProbePolicy(kernel, shortRead: true, useZeroSubmodeKernel: true);
        Tx(p, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434444E");
        Tx(p, "6C10F02701"); Rx(p, "6CF01067010000");
        p.BeforeTransmit(p.UploadPermissionMessage); Rx(p, "6CF010740044");
        return p;
    }

    private static void ZeroSubmodeUpload()
    {
        var plain = new AutoCalKernelProbePolicy(kernel, shortRead: true);
        var p = ZeroCopyReady();
        byte[][] before = plain.UploadMessages, after = p.UploadMessages;
        Require(p.UploadPermissionMessage.SequenceEqual(plain.UploadPermissionMessage) &&
            after[1].SequenceEqual(before[1]), "permission and execute packet remain byte-for-byte unchanged");
        Require(after[0].Length == 279 && after[0].AsSpan(0, 10).SequenceEqual(before[0].AsSpan(0, 10)),
            "RAM copy extent and header remain fixed");
        int[] dataChanges = Enumerable.Range(10, 267).Where(i => before[0][i] != after[0][i]).ToArray();
        Require(dataChanges.SequenceEqual(new[] { 0xD8 }) && before[0][0xD8] == 1 && after[0][0xD8] == 0,
            "only template byte differs in the267-byte RAM copy body");
        int oldSum = (before[0][277] << 8) | before[0][278];
        int newSum = (after[0][277] << 8) | after[0][278];
        Require(newSum == ((oldSum - 1) & 0xFFFF) && VpwUtilities.CalcBlockChecksum(after[0]) == newSum,
            "production packet builder recalculates upload checksum from effective bytes");
        Require(after[0].AsSpan(10, 267).SequenceEqual(p.KernelBytes.AsSpan(1760, 267)) &&
            after[1].AsSpan(10, 1760).SequenceEqual(p.KernelBytes.AsSpan(0, 1760)),
            "both exact upload fragments reconstruct the effective kernel");
        p.BeforeTransmit(after[0]); Rx(p, "6CF010760078");
        p.BeforeTransmit(after[1]); Rx(p, "6CF010768078");
        Require(p.RamCopyAttempts == 1 && p.RamExecuteAttempts == 1, "only exact derived upload authorized");
        var stale = ZeroCopyReady();
        Reject(() => stale.BeforeTransmit(before[0]), "original copy packet cannot substitute for selected variant");
        Require(stale.RamCopyAttempts == 0, "mismatched copy rejected before any copy authorization");
    }

    private static void ZeroSubmodeReply()
    {
        var p = ShortDataReady(true); Tx(p, ShortRequest);
        byte[] raw = ShortReply(0), snapshot = (byte[])raw.Clone();
        Require(raw.Length == 76 && raw[74] == 0x0E && raw[75] == 0x91 &&
            Convert.ToHexString(SHA256.HashData(raw)).ToLowerInvariant() ==
                "70db0cd94d2a5e53009cb96ad4e7435d403873f349e2d3a60f40113aeb5ebc95",
            "raw zero-submode reply has the independently derived exact checksum and digest");
        p.ObserveReceive(raw);
        Require(raw.SequenceEqual(snapshot) && p.LastReceive!.SequenceEqual(snapshot),
            "validation preserves raw zero-submode reply and checksum");
        Require(p.IsShortReadVerified && p.ReadBlockReplies == 1 && p.ReadBlockAttempts == 1 &&
            p.ReadImage.SequenceEqual(baseline.Value.Take(64)), "exact64-byte prefix verified");
        Require(!p.IsImageVerified && !p.IsImageReadComplete && !p.BaselineShaMatched &&
            p.CrcQueryAttempts == 0 && p.VerifiedCrcRanges == 0, "variant does not claim full image or CRC coverage");
        Tx(p, "6C10F020"); Rx(p, "6CF01060"); Tx(p, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434444E");
        Require(p.IsExitConfirmed && p.IsPostExitIdentityVerified, "verified prefix permits unchanged explicit exit and identity");

        var wrongSum = ShortDataReady(true); Tx(wrongSum, ShortRequest);
        byte[] unchangedChecksum = ShortReply(); unchangedChecksum[4] = 0;
        Reject(() => wrongSum.ObserveReceive(unchangedChecksum), "submode edit with original checksum must fail");
        Require(wrongSum.ReadBlockReplies == 0 && !wrongSum.IsShortReadVerified, "bad checksum grants no data coverage");
        var wrongData = ShortDataReady(true); Tx(wrongData, ShortRequest);
        byte[] different = ShortReply(0); different[10] ^= 1; VpwUtilities.AddBlockChecksum(different);
        Reject(() => wrongData.ObserveReceive(different), "checksum-valid different prefix still fails baseline pin");
        Reject(() => Tx(wrongData, "6C10F020"), "failed variant prefix cannot authorize exit");
    }

    private static void ZeroSubmodeRestrictions()
    {
        foreach ((bool full, bool shortRead) in new[] { (false, false), (true, false), (true, true) })
        {
            bool rejected = false;
            try { new AutoCalKernelProbePolicy(kernel, fullRead: full, shortRead: shortRead, useZeroSubmodeKernel: true); }
            catch (ArgumentException) { rejected = true; }
            Require(rejected, "variant restricted to exclusive short-read mode");
        }
        foreach (int offset in new[] { 0, 0x7AA, 0x7AE, 0x7B3 })
        {
            byte[] changed = (byte[])kernel.Clone(); changed[offset] ^= 1;
            Reject(() => new AutoCalKernelProbePolicy(changed, shortRead: true, useZeroSubmodeKernel: true),
                "all supplied variants rejected before internal derivation");
        }
        var zero = ShortDataReady(true); Tx(zero, ShortRequest);
        Reject(() => zero.ObserveReceive(ShortReply()), "variant refuses original01 reply despite valid checksum");
        var ordinary = ShortDataReady(); Tx(ordinary, ShortRequest);
        Reject(() => ordinary.ObserveReceive(ShortReply(0)), "default policy still refuses00 reply");
        foreach (string request in new[] { ShortRequest, "6C10F03D02000040000000", "6C10F03D05000000" })
        {
            var p = ShortDataReady(true); Tx(p, ShortRequest); p.ObserveReceive(ShortReply(0));
            Reject(() => Tx(p, request), "variant success cannot authorize replay CRC or erase");
        }
    }
}

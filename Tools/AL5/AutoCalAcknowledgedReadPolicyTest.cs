// SPDX-License-Identifier: GPL-3.0-only
// Exact ACK-plus-zero RAM variant and production policy tests. No transport I/O.
using System;
using System.Linq;
using System.Security.Cryptography;
using PcmHacking;

internal static partial class AutoCalKernelProbePolicyTest
{
    private const string ReadAck = "6DF010750154";
    private static AutoCalKernelProbePolicy AckPolicy() => new(kernel, shortRead: true,
        useZeroSubmodeKernel: true, prependReadAcknowledgement: true);

    private static void AcknowledgedKernelPin()
    {
        byte[] before = (byte[])kernel.Clone();
        var p = AckPolicy(); byte[] effective = p.KernelBytes;
        Require(kernel.SequenceEqual(before) && effective.Length == 2027,
            "fixed-length derivation preserves caller original bytes");
        Require(p.PrependReadAcknowledgement && p.UsesZeroSubmodeKernel && p.ReadReplySubmode == 0
            && p.ShortReadEnabled && !p.FullReadEnabled, "exclusive ACK-plus-zero prefix mode");
        Require(!p.ReadAcknowledgementObserved && p.ReadAcknowledgement == null,
            "selected ACK experiment does not imply an observed response");
        Require(p.EffectiveKernelSha256 == AutoCalKernelProbePolicy.ExpectedAcknowledgedKernelSha256
            && Convert.ToHexString(SHA256.HashData(effective)).ToLowerInvariant() ==
                "eca54a2661baa317c02f96cd19a4e4bdac5a79a4c264f5154662e12e1c519664",
            "independently derived exact effective pin");
        Require(effective.AsSpan(0x90, 4).SequenceEqual(Hex("67000702"))
            && effective.AsSpan(0x794, 22).SequenceEqual(Hex("41FA000C70066100FE4C6000FD3A6DF0107501544E71"))
            && effective[0x7AE] == 0, "three exact patch spans");
        int[] changes = Enumerable.Range(0, kernel.Length).Where(i => kernel[i] != effective[i]).ToArray();
        Require(changes.Length == 25 && changes.All(i => (i >= 0x90 && i < 0x94)
            || (i >= 0x794 && i < 0x7AA) || i == 0x7AE), "only the independently reviewed 25 bytes differ");
        var original = new AutoCalKernelProbePolicy(kernel, shortRead: true);
        Require(!original.PrependReadAcknowledgement && !original.ReadAcknowledgementObserved
            && original.EffectiveKernelSha256 == AutoCalKernelProbePolicy.ExpectedKernelSha256,
            "ordinary mode retains original exact asset and no ACK expectation");
        var zero = new AutoCalKernelProbePolicy(kernel, shortRead: true, useZeroSubmodeKernel: true);
        Require(!zero.PrependReadAcknowledgement && zero.EffectiveKernelSha256 ==
            AutoCalKernelProbePolicy.ExpectedZeroSubmodeKernelSha256, "prior zero-only experiment remains separate");
        effective[0] ^= 1;
        Require(p.KernelBytes[0] == before[0], "kernel getter cannot mutate owned derived clone");
        foreach (byte[] input in new[] { p.KernelBytes, zero.KernelBytes, kernel[..^1] })
            Reject(() => new AutoCalKernelProbePolicy(input, shortRead: true, useZeroSubmodeKernel: true,
                prependReadAcknowledgement: true), "never accept caller supplied variant or truncated source");
        foreach (bool full in new[] { false, true })
        foreach (bool shortRead in new[] { false, true })
        foreach (bool zeroMode in new[] { false, true })
        {
            if (!full && shortRead && zeroMode) continue;
            bool rejected = false;
            try { new AutoCalKernelProbePolicy(kernel, full, shortRead, zeroMode, true); }
            catch (ArgumentException) { rejected = true; }
            Require(rejected, "all other mode combinations reject before I/O");
        }
    }

    private static void AcknowledgedKernelUpload()
    {
        var p = AckPolicy(); var ordinary = new AutoCalKernelProbePolicy(kernel, shortRead: true);
        Require(p.UploadPermissionMessage.SequenceEqual(ordinary.UploadPermissionMessage),
            "upload permission and total kernel extent are unchanged");
        byte[][] messages = p.UploadMessages;
        Require(messages.Length == 2 && messages[0].Length == 279 && messages[1].Length == 1772,
            "observed two-upload envelope limits preserved");
        Require(messages[1].Skip(10).Take(1760).Concat(messages[0].Skip(10).Take(267)).SequenceEqual(p.KernelBytes),
            "two exact RAM payloads reconstruct the selected clone");
        foreach (byte[] message in messages)
            Require(VpwUtilities.CalcBlockChecksum(message) == ((message[^2] << 8) | message[^1]),
                "production upload checksum covers the modified bytes");
        Require(!messages[0].SequenceEqual(ordinary.UploadMessages[0]) && !messages[1].SequenceEqual(ordinary.UploadMessages[1]),
            "dispatch patch and stub affect their respective RAM packets");
        var ready = ShortDataReady(true, true);
        Require(ready.RamCopyAttempts == 1 && ready.RamExecuteAttempts == 1 && ready.IsKernelVerified,
            "ordinary exact copy execute and version gates still apply");
    }

    private static void AcknowledgedReadSuccess()
    {
        var p = ShortDataReady(true, true); Tx(p, ShortRequest);
        Require(p.CurrentPhase == "ReadAcknowledgementReply" && p.ReadBlockAttempts == 1
            && p.ReadBlockReplies == 0, "one unchanged read request awaits ACK first");
        int tx = p.TransmitAttempts, rx = p.ReceiveCount;
        byte[] ack = Hex(ReadAck), before = (byte[])ack.Clone();
        p.ObserveReceive(ack);
        Require(p.ReadAcknowledgementObserved && p.ReadAcknowledgement!.SequenceEqual(before)
            && p.LastReceive!.SequenceEqual(before) && p.ReceiveCount == rx + 1,
            "exact ACK preserved as one received frame");
        Require(p.CurrentPhase == "ReadBlockReply" && p.TransmitAttempts == tx && p.ReadBlockReplies == 0
            && !p.IsShortReadVerified && p.ComputedImageSha256 == null, "ACK grants no data coverage or additional transmit");
        ack[5] ^= 1; p.ReadAcknowledgement![0] ^= 1;
        Require(p.ReadAcknowledgement!.SequenceEqual(before), "ACK source and getter are defensively cloned");
        byte[] raw = ShortReply(0), saved = (byte[])raw.Clone(); p.ObserveReceive(raw);
        Require(raw.SequenceEqual(saved) && p.IsShortReadVerified && p.ReadBlockReplies == 1
            && p.ReadImage.SequenceEqual(baseline.Value.Take(64)), "original zero-submode checksum and exact prefix validate");
        Require(p.ReadAcknowledgement!.SequenceEqual(before) && !p.IsImageVerified && !p.IsImageReadComplete
            && p.CrcQueryAttempts == 0 && p.VerifiedCrcRanges == 0, "ACK retained without widening image or CRC claims");
        Tx(p, "6C10F020"); Rx(p, "6CF01060"); Tx(p, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434444E");
        Require(p.IsExitConfirmed && p.IsPostExitIdentityVerified, "unchanged explicit exit and ordinary identity follow verified prefix");
    }

    private static void AcknowledgedReadMissingOrMalformed()
    {
        var missing = ShortDataReady(true, true); Tx(missing, ShortRequest);
        Reject(() => missing.ObserveReceive(ShortReply(0)), "data before required ACK must fault");
        Require(!missing.ReadAcknowledgementObserved && !missing.IsShortReadVerified && missing.ReadBlockReplies == 0,
            "missing ACK cannot create coverage");
        Reject(() => Rx(missing, ReadAck), "later ACK cannot recover a faulted ordering");
        foreach (string attempt in new[] { ShortRequest, "6C10F020", "6C10F03D02000040000000", "6C10F03D05000000" })
        {
            var p = ShortDataReady(true, true); Tx(p, ShortRequest);
            Reject(() => Tx(p, attempt), "no retry exit CRC or erase while ACK is missing");
        }
        foreach (byte[] bad in new[] { Hex("6DF01075"), Hex("6DF0107501"), Hex("6DF01075015400"),
            Hex("6CF010750154"), Hex("6D10F0750154"), Hex("6DF010750054"), Hex("6DF010750155"), Hex("6DF010") })
        {
            var p = ShortDataReady(true, true); Tx(p, ShortRequest);
            Reject(() => p.ObserveReceive(bad), "wrong exact ACK route extent or bytes");
            Require(!p.ReadAcknowledgementObserved && p.ReadBlockReplies == 0 && p.LastReceive!.SequenceEqual(bad),
                "malformed ACK retained as evidence but not accepted");
        }
        var negative = ShortDataReady(true, true); Tx(negative, ShortRequest);
        Reject(() => Rx(negative, "6CF0107F3531"), "negative Mode35 reply faults while awaiting ACK");
    }

    private static void AcknowledgedReadOrderingAndIsolation()
    {
        foreach (bool zero in new[] { false, true })
        {
            var p = ShortDataReady(zero); Tx(p, ShortRequest);
            Reject(() => Rx(p, ReadAck), "ordinary and zero-only modes reject unexpected ACK");
            Require(!p.ReadAcknowledgementObserved && !p.IsShortReadVerified, "no accidental ACK privilege in existing modes");
        }
        Reject(() => Rx(AckPolicy(), ReadAck), "ACK before initial identity");
        Reject(() => Rx(ShortDataReady(true, true), ReadAck), "ACK before fixed read request");
        var duplicate = ShortDataReady(true, true); Tx(duplicate, ShortRequest); Rx(duplicate, ReadAck);
        Reject(() => Rx(duplicate, ReadAck), "duplicate ACK before data");
        Require(duplicate.ReadAcknowledgementObserved && duplicate.ReadBlockReplies == 0, "first ACK remains evidence after duplicate failure");
        foreach (int state in new[] { 0, 1, 2 })
        {
            var p = ShortDataReady(true, true); Tx(p, ShortRequest); Rx(p, ReadAck); p.ObserveReceive(ShortReply(0));
            if (state >= 1) Tx(p, "6C10F020");
            if (state >= 2) { Rx(p, "6CF01060"); Tx(p, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434444E"); }
            Reject(() => Rx(p, ReadAck), "ACK after verified data, exit or completed session");
        }
        foreach (byte[] invalidData in new[] { ShortReply(1), ShortReply(0)[..^1] })
        {
            var p = ShortDataReady(true, true); Tx(p, ShortRequest); Rx(p, ReadAck);
            Reject(() => p.ObserveReceive(invalidData), "ACK never relaxes exact data submode or extent");
        }
        var sum = ShortDataReady(true, true); Tx(sum, ShortRequest); Rx(sum, ReadAck);
        byte[] invalidSum = ShortReply(0); invalidSum[^1] ^= 1;
        Reject(() => sum.ObserveReceive(invalidSum), "ACK cannot bypass raw block checksum");
        var onlyAck = ShortDataReady(true, true); Tx(onlyAck, ShortRequest); Rx(onlyAck, ReadAck);
        Reject(() => Tx(onlyAck, "6C10F020"), "ACK without verified data cannot authorize reset");
    }

    private static void AcknowledgedReadHostBoundary()
    {
        var p = AckPolicy(); var g = HostReady(p);
        HostTx(p, g, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434");
        HostTx(p, g, "6C10F02701"); Rx(p, "6CF01067010000");
        HostTx(p, g, p.UploadPermissionMessage); Rx(p, "6CF010740044");
        HostTx(p, g, p.UploadMessages[0]); Rx(p, "6CF010760078");
        HostTx(p, g, p.UploadMessages[1]); Rx(p, "6CF010768078");
        HostTx(p, g, "6C10F03D00"); Rx(p, "6CF0107D006AB178EC36");
        HostTx(p, g, "6C10F03D01"); Rx(p, "6CF0107D0100894471");
        HostTx(p, g, ShortRequest); Rx(p, ReadAck);
        Reject(() => HostFinish(g, new ProbeProfile(true).Requests[5]), "ACK alone does not authorize adapter cleanup");
        p.ObserveReceive(ShortReply(0));
        HostTx(p, g, "6C10F020"); Rx(p, "6CF01060"); HostTx(p, g, "6C10F03C0A"); Rx(p, "6CF0107C0A00E7C434");
        foreach (byte[] frame in new ProbeProfile(true).Requests.Skip(5)) HostFinish(g, frame);
        Require(g.VpwPayloadCommandsCompleted == 10 && p.ReadBlockAttempts == 1 && p.ReadBlockReplies == 1
            && p.ReadAcknowledgementObserved && p.IsPostExitIdentityVerified,
            "same ten zero-seed host requests; new ACK is only a required receive");
        Require(p.CrcQueryAttempts == 0 && !p.IsImageVerified, "host guard scope does not expand to CRC or full image");
    }
}

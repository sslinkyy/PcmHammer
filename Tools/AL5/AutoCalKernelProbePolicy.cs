// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using PcmHacking;

/// <summary>
/// Closed, offline-testable VPW policy for one E54 RAM-kernel qualification.
/// This class performs no I/O. Call BeforeTransmit immediately before forwarding
/// a complete VPW message, and ObserveReceive for every received VPW message.
/// A permitted transmit is an attempt, not proof that bytes reached the bus.
/// </summary>
public sealed class AutoCalKernelProbePolicy
{
    public const uint ExpectedOperatingSystem = 15189044;
    public const ulong ExpectedKernelVersion = 0x6AB178EC36UL;
    public const int ExpectedKernelLength = 2027;
    public const int MaximumTransmitBytes = 1772;
    public const int KernelBaseAddress = 0xFF9100;
    public const string ExpectedKernelSha256 = "8294b899c153b513cd1307ac4c6654c2720832779f40c19aac7100a4b864929a";
    public const string DefaultKernelPath = @"C:\Codex Projects\Car Tuning\To tune\My Original Stock Tunes\iMob Racing MultiMap OS\PcmHammer_E54_RAM_Survey_Bench_v0_1\Kernel-E54.bin";
    public const int FullReadLength = 512 * 1024;
    public const int ReadBlockLength = 4096;
    public const int ReadBlockCount = FullReadLength / ReadBlockLength;
    public const int ShortReadLength = 64;
    public const string ExpectedShortReadSha256 = "5b20a24c0d5c5618de617dd929c4baffe7ba4cf151648398f68f0105bd43a5d9";
    public const string ExpectedBaselineSha256 = "a3b010af7e04df03be699198920aac26ba0645c2ad608e72eacf0bc3970beb58";
    public const string DefaultBaselinePath = @"C:\Codex Projects\Car Tuning\To tune\AL5 Transmission Work\PcmHammer\LocalOnly\usb_capture_setup_20261030\e54_gt_pcmhammer_write_01\E54_before_test.bin";
    public const int MaximumCrcQueriesPerRange = 6;
    // Existing verifier: one range-start notification, then up to six polls;
    // two CRC-boundary notifications plus one per data block, and startup budget.
    public const int MaximumFullReadToolPresentAttempts = 32 + ReadBlockCount + 2 + 7 * (1 + MaximumCrcQueriesPerRange);
    // Intel 28F400B order, pinned by actual GT read/CRC transcript and FlashChip.
    private static readonly uint[] crcAddresses = { 0x60000, 0x40000, 0x20000, 0x8000, 0x6000, 0x4000, 0 };
    private static readonly uint[] crcSizes = { 0x20000, 0x20000, 0x20000, 0x18000, 0x2000, 0x2000, 0x4000 };

    // A developer-operation budget, not a protocol or firmware capacity claim.
    public const int MaximumToolPresentAttempts = 32;
    private enum Phase
    {
        InitialIdentity, InitialIdentityReply, Preparation, SeedReply, Key,
        KeyReply, UploadPermission, UploadPermissionReply, RamCopy, RamCopyReply,
        RamExecute, RamExecuteReply, KernelVersion, KernelVersionReply,
        FlashIdentity, FlashIdentityReply, ReadBlock, ReadBlockReply, ReadCrc, ReadCrcReply,
        Exit, ExitReply, FinalIdentity, FinalIdentityReply, Complete
    }
    private Phase phase;
    private readonly byte[] kernel;
    private readonly byte[] permission;
    private readonly byte[][] upload;
    private ushort seed;
    private byte[]? lastReceive;
    private byte[]? copyAck;
    private byte[]? executeAck;
    private byte[]? initialIdentity;
    private byte[]? finalIdentity;
    private byte[]? lastAuthorizedTransmit;
    private readonly byte[] readImage;
    private readonly int[] crcQueryAttemptsByRange = new int[7];
    private readonly Protocol protocol = new Protocol();

    public string? Failure { get; private set; }
    public string CurrentPhase => phase.ToString();
    public bool IsInitialIdentityVerified { get; private set; }
    public bool IsKernelVerified { get; private set; }
    public bool IsExitConfirmed { get; private set; }
    public bool IsPostExitIdentityVerified { get; private set; }
    public bool FullReadEnabled { get; }
    public bool ShortReadEnabled { get; }
    public bool ReadEnabled => FullReadEnabled || ShortReadEnabled;
    public bool IsShortReadVerified { get; private set; }
    public bool IsFlashIdentityVerified { get; private set; }
    public bool IsImageReadComplete => FullReadEnabled && ReadBlockReplies == ReadBlockCount;
    public bool IsImageVerified { get; private set; }
    public bool BaselineShaMatched { get; private set; }
    public string? ComputedImageSha256 { get; private set; }
    public int ReadBlockAttempts { get; private set; }
    public int ReadBlockReplies { get; private set; }
    public int CrcQueryAttempts { get; private set; }
    public int VerifiedCrcRanges { get; private set; }
    public int ToolPresentAttemptLimit => FullReadEnabled ? MaximumFullReadToolPresentAttempts : MaximumToolPresentAttempts;
    // The counters describe valid coverage of this defensive image snapshot.
    // Partial images must not be represented as a completed read by callers.
    public byte[] ReadImage => (byte[])readImage.Clone();
    public byte[][] CrcRequests => crcAddresses.Select((address, index) =>
        protocol.CreateCrcQuery(address, crcSizes[index]).GetBytes()).ToArray();
    public int TransmitAttempts { get; private set; }
    public int AuthorizedTransmitCount => TransmitAttempts;
    public byte[]? LastAuthorizedTransmit => Clone(lastAuthorizedTransmit);
    public int ReceiveCount { get; private set; }
    public int UnrelatedReceiveCount { get; private set; }
    public int ToolPresentAttempts { get; private set; }
    public int SuppressionAttempts { get; private set; }
    public int SeedAttempts { get; private set; }
    public int KeyAttempts { get; private set; }
    public int RamCopyAttempts { get; private set; }
    public int RamExecuteAttempts { get; private set; }
    public byte[] KernelBytes => (byte[])kernel.Clone();
    public byte[] UploadPermissionMessage => (byte[])permission.Clone();
    public byte[][] UploadMessages => upload.Select(x => (byte[])x.Clone()).ToArray();
    public byte[]? LastReceive => Clone(lastReceive);
    public byte[]? RamCopyAcknowledgement => Clone(copyAck);
    public byte[]? RamExecuteAcknowledgement => Clone(executeAck);
    public byte[]? InitialIdentityReply => Clone(initialIdentity);
    public byte[]? PostExitIdentityReply => Clone(finalIdentity);

    public AutoCalKernelProbePolicy(byte[] pinnedKernel, bool fullRead = false, bool shortRead = false)
    {
        if (pinnedKernel == null) throw new ArgumentNullException(nameof(pinnedKernel));
        if (fullRead && shortRead) throw new ArgumentException("Full-image and short-prefix read modes are mutually exclusive.");
        kernel = (byte[])pinnedKernel.Clone();
        FullReadEnabled = fullRead;
        ShortReadEnabled = shortRead;
        readImage = fullRead ? new byte[FullReadLength] : shortRead ? new byte[ShortReadLength] : Array.Empty<byte>();
        if (kernel.Length != ExpectedKernelLength ||
            !Convert.ToHexString(SHA256.HashData(kernel)).Equals(ExpectedKernelSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Kernel bytes do not match the previously captured E54 asset.");

        var info = new OSIDInfo(ExpectedOperatingSystem);
        if (info.HardwareType != PcmType.E54 || info.LoaderRequired || info.KernelBaseAddress != KernelBaseAddress || info.KeyAlgorithm != 54)
            throw new InvalidDataException("Current PcmHammer E54 metadata differs from the pinned probe contract.");
        var protocol = new Protocol();
        permission = protocol.CreateUploadRequest(info, kernel.Length).GetBytes();
        if (!Equal(permission, "6C10F0340007EBFF9100"))
            throw new InvalidDataException("Current PcmHammer upload-permission encoding differs from the probe contract.");

        // Mirror PCMExecute's descending RAM chunks at the observed AutoCal TX cap.
        // These two fragments were exercised by e54_kernel_info_01.json;
        // this file-only policy does not itself establish physical qualification.
        const int firstLength = MaximumTransmitBytes - 12; // 1760 / 0x6E0
        upload = new[] {
            protocol.CreateBlockMessage(kernel, firstLength, kernel.Length - firstLength,
                KernelBaseAddress + firstLength, BlockCopyType.Copy).GetBytes(),
            protocol.CreateBlockMessage(kernel, 0, firstLength,
                KernelBaseAddress, BlockCopyType.Execute).GetBytes()
        };
        if (upload[0].Length != 279 || upload[1].Length != MaximumTransmitBytes ||
            !Starts(upload[0], "6D10F03600010BFF97E0") || !Starts(upload[1], "6D10F0368006E0FF9100"))
            throw new InvalidDataException("Current PcmHammer RAM-block encoding differs from the probe contract.");
    }

    /// <summary>
    /// Authorize one complete VPW submission. Every identity/security/upload/query/
    /// exit command is allowed once; only fixed current-range CRC polls may repeat.
    /// Shared Vehicle retry loops therefore cannot
    /// replay an uncertain RAM copy or execution. Native partial writes remain the
    /// AutoCalChannel's responsibility and must not call this method again.
    /// </summary>
    public void BeforeTransmit(byte[] bytes)
    {
        Healthy();
        if (bytes == null) throw new ArgumentNullException(nameof(bytes));
        if (Equal(bytes, "8CFEF03F") && IsInitialIdentityVerified && phase < Phase.ExitReply)
        {
            if (ToolPresentAttempts >= ToolPresentAttemptLimit) Reject("Tool-present attempt budget exhausted.");
            ToolPresentAttempts++; Authorize(bytes); return;
        }
        if (Equal(bytes, "6CFEF02800") && phase == Phase.Preparation && SuppressionAttempts == 0)
        {
            SuppressionAttempts++; Authorize(bytes); return;
        }

        bool permitted = false;
        switch (phase)
        {
            case Phase.InitialIdentity:
                permitted = Equal(bytes, "6C10F03C0A");
                if (permitted) phase = Phase.InitialIdentityReply;
                break;
            case Phase.Preparation:
                permitted = Equal(bytes, "6C10F02701");
                if (permitted) { phase = Phase.SeedReply; SeedAttempts++; }
                break;
            case Phase.Key:
                permitted = bytes.SequenceEqual(new Protocol().CreateUnlockRequest(KeyAlgorithm.GetKey(54, seed)).GetBytes());
                if (permitted) { phase = Phase.KeyReply; KeyAttempts++; }
                break;
            case Phase.UploadPermission:
                permitted = bytes.SequenceEqual(permission);
                if (permitted) phase = Phase.UploadPermissionReply;
                break;
            case Phase.RamCopy:
                permitted = bytes.SequenceEqual(upload[0]);
                if (permitted) { phase = Phase.RamCopyReply; RamCopyAttempts++; }
                break;
            case Phase.RamExecute:
                permitted = bytes.SequenceEqual(upload[1]);
                if (permitted)
                {
                    // Pinned by the independent AutoCal copy-only experiment
                    // e54_ram_copy_01.json (2026-10-30). Unknown suffixes may be
                    // observed by copy-only mode, but never authorize Execute.
                    // This is an observed-response prerequisite, not RAM readback.
                    if (copyAck == null || !Equal(copyAck, "6CF010760078"))
                        Reject("RAM execution requires the exact observed stock Copy reply 6CF010760078.");
                    phase = Phase.RamExecuteReply; RamExecuteAttempts++;
                }
                break;
            case Phase.KernelVersion:
                permitted = Equal(bytes, "6C10F03D00");
                if (permitted) phase = Phase.KernelVersionReply;
                break;
            case Phase.FlashIdentity:
                permitted = Equal(bytes, "6C10F03D01");
                if (permitted) phase = Phase.FlashIdentityReply;
                break;
            case Phase.ReadBlock:
                int length = ShortReadEnabled ? ShortReadLength : ReadBlockLength;
                permitted = bytes.SequenceEqual(protocol.CreateReadRequest(ReadBlockReplies * length, length).GetBytes());
                if (permitted) { phase = Phase.ReadBlockReply; ReadBlockAttempts++; }
                break;
            case Phase.ReadCrc:
            case Phase.ReadCrcReply:
                permitted = bytes.SequenceEqual(protocol.CreateCrcQuery(crcAddresses[VerifiedCrcRanges], crcSizes[VerifiedCrcRanges]).GetBytes());
                if (permitted)
                {
                    if (crcQueryAttemptsByRange[VerifiedCrcRanges] >= MaximumCrcQueriesPerRange)
                        Reject("CRC query budget exhausted for the fixed current range.");
                    crcQueryAttemptsByRange[VerifiedCrcRanges]++; CrcQueryAttempts++; phase = Phase.ReadCrcReply;
                }
                break;
            case Phase.Exit:
                permitted = Equal(bytes, "6C10F020");
                if (permitted) phase = Phase.ExitReply;
                break;
            case Phase.FinalIdentity:
                permitted = Equal(bytes, "6C10F03C0A");
                if (permitted) phase = Phase.FinalIdentityReply;
                break;
        }
        if (!permitted) Reject("VPW request is outside the fixed RAM-kernel probe at " + phase + ": " + Convert.ToHexString(bytes));
        Authorize(bytes);
    }

    /// <summary>
    /// Correlate a received VPW message. Unrelated messages are counted and retained
    /// by the caller's journal; malformed or negative responses for the pending
    /// operation fault the policy. This does not discard bytes from any transport.
    /// </summary>
    public void ObserveReceive(byte[] bytes)
    {
        if (bytes == null) throw new ArgumentNullException(nameof(bytes));
        lastReceive = (byte[])bytes.Clone(); ReceiveCount++;
        Healthy();
        if (phase == Phase.ReadBlockReply && Starts(bytes, "6DF01036"))
        {
            int length = ShortReadEnabled ? ShortReadLength : ReadBlockLength;
            int address = ReadBlockReplies * length;
            byte[] expected = protocol.CreateReadRequest(address, length).GetBytes();
            expected[1] = 0xF0; expected[2] = 0x10; expected[3] = 0x36;
            if (bytes.Length != length + 12 || !bytes.AsSpan(0, 10).SequenceEqual(expected))
                Reject("Read block has an unexpected exact extent, submode, length or address.");
            Response<byte[]> decoded = protocol.ParsePayload(new Message(bytes), length, address);
            if (decoded.Status != ResponseStatus.Success || decoded.Value.Length != length)
                Reject("Read block failed production payload/checksum validation.");
            Buffer.BlockCopy(decoded.Value, 0, readImage, address, length);
            ReadBlockReplies++;
            if (ShortReadEnabled)
            {
                ComputedImageSha256 = Convert.ToHexString(SHA256.HashData(readImage)).ToLowerInvariant();
                if (!ComputedImageSha256.Equals(ExpectedShortReadSha256, StringComparison.Ordinal))
                    Reject("Short read differs from the exact first64 bytes of the pinned E54 baseline.");
                IsShortReadVerified = true;
                // A matching prefix establishes neither a complete image nor its CRCs.
                phase = Phase.Exit;
                return;
            }
            if (ReadBlockReplies == ReadBlockCount)
            {
                ComputedImageSha256 = Convert.ToHexString(SHA256.HashData(readImage)).ToLowerInvariant();
                BaselineShaMatched = ComputedImageSha256.Equals(ExpectedBaselineSha256, StringComparison.Ordinal);
                if (!BaselineShaMatched) Reject("Full read differs from the exact pre-test E54 baseline.");
                phase = Phase.ReadCrc;
            }
            else phase = Phase.ReadBlock;
            return;
        }
        int expectedMode = ExpectedMode();
        if (expectedMode < 0 || !Starts(bytes, "6CF010")) { UnrelatedReceiveCount++; return; }
        if (bytes.Length >= 5 && bytes[3] == 0x7F && bytes[4] == expectedMode)
            Reject("E54 rejected the pending request: " + Convert.ToHexString(bytes));
        if (bytes.Length < 4 || bytes[3] != expectedMode + 0x40) { UnrelatedReceiveCount++; return; }

        switch (phase)
        {
            case Phase.InitialIdentityReply:
            case Phase.FinalIdentityReply:
                if ((bytes.Length != 9 && bytes.Length != 11) || !Starts(bytes, "6CF0107C0A00E7C434"))
                    Reject("Identity reply differs from the pinned E54 OSID/extent: " + Convert.ToHexString(bytes));
                if (phase == Phase.InitialIdentityReply)
                {
                    initialIdentity = (byte[])bytes.Clone(); IsInitialIdentityVerified = true; phase = Phase.Preparation;
                }
                else
                {
                    finalIdentity = (byte[])bytes.Clone(); IsPostExitIdentityVerified = true; phase = Phase.Complete;
                }
                return;
            case Phase.SeedReply:
                if (bytes.Length != 7 || !Starts(bytes, "6CF0106701"))
                    Reject("Expected one complete two-byte E54 seed, not a lockout/status reply: " + Convert.ToHexString(bytes));
                seed = (ushort)((bytes[5] << 8) | bytes[6]);
                if (seed == 0xFFFF) Reject("Unprogrammed/ambiguous FFFF seed is outside the pinned bench probe.");
                phase = seed == 0 ? Phase.UploadPermission : Phase.Key;
                return;
            case Phase.KeyReply:
                if (!Equal(bytes, "6CF010670234")) Reject("Unlock reply did not exactly grant access: " + Convert.ToHexString(bytes));
                phase = Phase.UploadPermission; return;
            case Phase.UploadPermissionReply:
                if (!Equal(bytes, "6CF010740044")) Reject("Unexpected upload-permission reply: " + Convert.ToHexString(bytes));
                phase = Phase.RamCopy; return;
            case Phase.RamCopyReply:
            case Phase.RamExecuteReply:
                byte expectedSubmode = phase == Phase.RamCopyReply ? (byte)0 : (byte)0x80;
                if (bytes.Length != 6 || bytes[4] != expectedSubmode)
                    Reject("RAM-upload response has wrong extent or submode: " + Convert.ToHexString(bytes));
                // The stock-ROM final byte's meaning remains opaque. Copy-only
                // observation preserves all values; Execute requires the exact
                // observed reply above. A post-Execute reply is also pinned to
                // earlier captures. Neither ACK proves execution or RAM equality.
                if (phase == Phase.RamCopyReply)
                { copyAck = (byte[])bytes.Clone(); phase = Phase.RamExecute; }
                else
                {
                    executeAck = (byte[])bytes.Clone();
                    if (!Equal(bytes, "6CF010768078"))
                        Reject("RAM Execute reply differs from the previously observed 6CF010768078.");
                    phase = Phase.KernelVersion;
                }
                return;
            case Phase.KernelVersionReply:
                if (!Equal(bytes, "6CF0107D006AB178EC36")) Reject("Kernel identity differs from the pinned asset: " + Convert.ToHexString(bytes));
                IsKernelVerified = true; phase = ReadEnabled ? Phase.FlashIdentity : Phase.Exit; return;
            case Phase.FlashIdentityReply:
                if (!Equal(bytes, "6CF0107D0100894471")) Reject("Flash identity differs from the pinned Intel 28F400B baseline.");
                IsFlashIdentityVerified = true; phase = Phase.ReadBlock; return;
            case Phase.ReadCrcReply:
                byte[] expectedCrc = protocol.CreateCrcQuery(crcAddresses[VerifiedCrcRanges], crcSizes[VerifiedCrcRanges]).GetBytes();
                expectedCrc[1] = 0xF0; expectedCrc[2] = 0x10; expectedCrc[3] = 0x7D;
                if (bytes.Length != 15 || !bytes.AsSpan(0, 11).SequenceEqual(expectedCrc))
                    Reject("CRC reply differs from the exact requested range/extent.");
                uint observedCrc = ((uint)bytes[11] << 24) | ((uint)bytes[12] << 16) | ((uint)bytes[13] << 8) | bytes[14];
                uint calculatedCrc = new Crc().GetCrc(readImage, crcAddresses[VerifiedCrcRanges], crcSizes[VerifiedCrcRanges]);
                if (observedCrc != calculatedCrc) Reject("Controller CRC differs from the completed baseline-matching read.");
                VerifiedCrcRanges++;
                if (VerifiedCrcRanges == crcAddresses.Length) { IsImageVerified = true; phase = Phase.Exit; }
                else phase = Phase.ReadCrc;
                return;
            case Phase.ExitReply:
                if (!Equal(bytes, "6CF01060")) Reject("Unexpected exit acknowledgement: " + Convert.ToHexString(bytes));
                IsExitConfirmed = true; phase = Phase.FinalIdentity; return;
            default:
                UnrelatedReceiveCount++; return;
        }
    }

    private int ExpectedMode()
    {
        switch (phase)
        {
            case Phase.InitialIdentityReply: case Phase.FinalIdentityReply: return 0x3C;
            case Phase.SeedReply: case Phase.KeyReply: return 0x27;
            case Phase.UploadPermissionReply: return 0x34;
            case Phase.RamCopyReply: case Phase.RamExecuteReply: return 0x36;
            case Phase.KernelVersionReply: return 0x3D;
            case Phase.FlashIdentityReply: case Phase.ReadCrcReply: return 0x3D;
            case Phase.ReadBlockReply: return 0x35;
            case Phase.ExitReply: return 0x20;
            default: return -1;
        }
    }
    private void Healthy()
    {
        if (Failure != null) throw new InvalidOperationException("Probe policy is faulted: " + Failure);
    }
    private void Authorize(byte[] bytes)
    {
        lastAuthorizedTransmit = (byte[])bytes.Clone();
        TransmitAttempts++;
    }
    private void Reject(string reason)
    {
        Failure ??= reason;
        throw new InvalidOperationException(reason);
    }
    private static byte[]? Clone(byte[]? bytes) => bytes == null ? null : (byte[])bytes.Clone();
    private static bool Equal(byte[] bytes, string hex) => bytes.SequenceEqual(Convert.FromHexString(hex));
    private static bool Starts(byte[] bytes, string hex)
    {
        byte[] prefix = Convert.FromHexString(hex);
        return bytes.Length >= prefix.Length && bytes.AsSpan(0, prefix.Length).SequenceEqual(prefix);
    }
}

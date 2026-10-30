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

    // A developer-operation budget, not a protocol or firmware capacity claim.
    public const int MaximumToolPresentAttempts = 32;
    private enum Phase
    {
        InitialIdentity, InitialIdentityReply, Preparation, SeedReply, Key,
        KeyReply, UploadPermission, UploadPermissionReply, RamCopy, RamCopyReply,
        RamExecute, RamExecuteReply, KernelVersion, KernelVersionReply,
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

    public string? Failure { get; private set; }
    public string CurrentPhase => phase.ToString();
    public bool IsInitialIdentityVerified { get; private set; }
    public bool IsKernelVerified { get; private set; }
    public bool IsExitConfirmed { get; private set; }
    public bool IsPostExitIdentityVerified { get; private set; }
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

    public AutoCalKernelProbePolicy(byte[] pinnedKernel)
    {
        if (pinnedKernel == null) throw new ArgumentNullException(nameof(pinnedKernel));
        kernel = (byte[])pinnedKernel.Clone();
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
        // These exact two fragments have NOT yet been physically qualified on AutoCal.
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
    /// exit command is allowed once. Shared Vehicle retry loops therefore cannot
    /// replay an uncertain RAM copy or execution. Native partial writes remain the
    /// AutoCalChannel's responsibility and must not call this method again.
    /// </summary>
    public void BeforeTransmit(byte[] bytes)
    {
        Healthy();
        if (bytes == null) throw new ArgumentNullException(nameof(bytes));
        if (Equal(bytes, "8CFEF03F") && IsInitialIdentityVerified && phase < Phase.ExitReply)
        {
            if (ToolPresentAttempts >= MaximumToolPresentAttempts) Reject("Tool-present attempt budget exhausted.");
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
                if (permitted) { phase = Phase.RamExecuteReply; RamExecuteAttempts++; }
                break;
            case Phase.KernelVersion:
                permitted = Equal(bytes, "6C10F03D00");
                if (permitted) phase = Phase.KernelVersionReply;
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
                // The stock-ROM final byte is opaque (single Execute previously
                // returned 0x78). Do not equate it with running-kernel flash status.
                // No programming or execution success is claimed from this ACK.
                if (phase == Phase.RamCopyReply)
                { copyAck = (byte[])bytes.Clone(); phase = Phase.RamExecute; }
                else
                { executeAck = (byte[])bytes.Clone(); phase = Phase.KernelVersion; }
                return;
            case Phase.KernelVersionReply:
                if (!Equal(bytes, "6CF0107D006AB178EC36")) Reject("Kernel identity differs from the pinned asset: " + Convert.ToHexString(bytes));
                IsKernelVerified = true; phase = Phase.Exit; return;
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

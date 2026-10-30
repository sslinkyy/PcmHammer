// SPDX-License-Identifier: GPL-3.0-only
using PcmHacking;

// The VPW policy authorizes at the Device boundary. This guard binds each
// resulting host command to exactly that authorization before native I/O.
// Setup and cleanup remain exact and cannot be substituted by VPW traffic.
internal sealed class KernelRequestGuard : RequestWriteGuard
{
    readonly AutoCalKernelProbePolicy policy;
    readonly bool copyOnly;
    readonly bool recordedReadSetup;
    readonly byte[][] setup = new ProbeProfile(true).Requests.Take(4).ToArray();
    readonly byte[][] cleanup = new ProbeProfile(true).Requests.Skip(5).ToArray();
    readonly byte[][] readPreparation = {
        AutoCalHostFrame.EncodeLongHeader(0x8603, 7, 0, new byte[] { 1, 0, 0xF4, 1 }),
        AutoCalHostFrame.EncodeLongHeader(0x8604, 7, 0, new byte[] { 1, 0, 0x10, 0, 0, 0 }) };
    int setupIndex, cleanupIndex, consumedAuthorizations;
    int preparationIndex;
    bool ordinaryRestored;
    public KernelRequestGuard(AutoCalKernelProbePolicy policy, bool copyOnly = false, bool recordedReadSetup = false)
    {
        if (recordedReadSetup && (copyOnly || !policy.ShortReadEnabled))
            throw new ArgumentException("Recorded read configuration is confined to the prefix diagnostic.");
        this.policy = policy; this.copyOnly = copyOnly; this.recordedReadSetup = recordedReadSetup;
    }

    protected override void ValidateNewCommand(byte[] bytes)
    {
        if (setupIndex < setup.Length)
        {
            if (!bytes.SequenceEqual(setup[setupIndex])) throw new InvalidOperationException("Unexpected kernel-probe setup command.");
            setupIndex++;
            return;
        }
        if (policy.Failure != null) throw new InvalidOperationException("Faulted policy cannot authorize host configuration.");
        if (recordedReadSetup && policy.IsInitialIdentityVerified && preparationIndex < readPreparation.Length)
        {
            if (policy.SuppressionAttempts != 0 || policy.SeedAttempts != 0 || policy.RamCopyAttempts != 0
                || consumedAuthorizations != policy.AuthorizedTransmitCount
                || !bytes.SequenceEqual(readPreparation[preparationIndex]))
                throw new InvalidOperationException("Exact recorded configuration must follow identity before any preparation traffic.");
            preparationIndex++;
            return;
        }
        if (recordedReadSetup && policy.IsKernelVerified && !ordinaryRestored)
        {
            if (preparationIndex != readPreparation.Length || policy.IsFlashIdentityVerified
                || consumedAuthorizations != policy.AuthorizedTransmitCount || !bytes.SequenceEqual(cleanup[0]))
                throw new InvalidOperationException("Exact zero-form configuration must follow kernel verification before flash identification.");
            ordinaryRestored = true;
            return;
        }
        if (policy.IsPostExitIdentityVerified)
        {
            if (copyOnly || !policy.IsKernelVerified || !policy.IsExitConfirmed || policy.Failure != null
                || consumedAuthorizations != policy.AuthorizedTransmitCount
                || cleanupIndex >= cleanup.Length || !bytes.SequenceEqual(cleanup[cleanupIndex]))
                throw new InvalidOperationException("Kernel-probe cleanup requires verified execution, exit and identity.");
            cleanupIndex++;
            return;
        }
        byte[]? allowed = policy.LastAuthorizedTransmit;
        if (copyOnly && (policy.RamExecuteAttempts != 0 || policy.RamCopyAcknowledgement != null))
            throw new InvalidOperationException("Copy-only observation cannot execute or submit another command after the copy acknowledgement.");
        if (policy.Failure != null || cleanupIndex != 0 || allowed == null
            || policy.AuthorizedTransmitCount != consumedAuthorizations + 1
            || !bytes.SequenceEqual(AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, allowed)))
            throw new InvalidOperationException("Host VPW command does not match one fresh policy authorization.");
        consumedAuthorizations++;
    }
}

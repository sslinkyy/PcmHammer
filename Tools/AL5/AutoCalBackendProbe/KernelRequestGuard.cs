// SPDX-License-Identifier: GPL-3.0-only
using PcmHacking;

// The VPW policy authorizes at the Device boundary. This guard binds each
// resulting host command to exactly that authorization before native I/O.
// Setup and cleanup remain exact and cannot be substituted by VPW traffic.
internal sealed class KernelRequestGuard : RequestWriteGuard
{
    readonly AutoCalKernelProbePolicy policy;
    readonly bool copyOnly;
    readonly byte[][] setup = new ProbeProfile(true).Requests.Take(4).ToArray();
    readonly byte[][] cleanup = new ProbeProfile(true).Requests.Skip(5).ToArray();
    int setupIndex, cleanupIndex, consumedAuthorizations;
    public KernelRequestGuard(AutoCalKernelProbePolicy policy, bool copyOnly = false)
    { this.policy = policy; this.copyOnly = copyOnly; }

    protected override void ValidateNewCommand(byte[] bytes)
    {
        if (setupIndex < setup.Length)
        {
            if (!bytes.SequenceEqual(setup[setupIndex])) throw new InvalidOperationException("Unexpected kernel-probe setup command.");
            setupIndex++;
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

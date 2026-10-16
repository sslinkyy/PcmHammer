// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    public enum AL5ModeledSenderState { Unobserved, Returned, TimedOutWithSoftwareReentry }
    public enum AL5LoaderModelReplyReason
    {
        ExpectedReply, SenderUnobserved, SenderTimeout, ReplyMissing, MalformedReply,
        NativeFailure, UnexpectedReply, StackUnknown, NonzeroStackDelta, ProgramCoverageUnknown, ProgramCoverageMismatch
    }

    /// <summary>Constructed three-byte loader body and emulator facts, not wire delivery evidence.</summary>
    public sealed class AL5LoaderModelResult
    {
        public AL5LoaderModelResult(byte[]? responseBody, AL5ModeledSenderState senderState, int? stackDelta,
            int? modeledProgramStartAddress = null, int? modeledProgramBytes = null)
        {
            if (!Enum.IsDefined(typeof(AL5ModeledSenderState), senderState))
                throw new ArgumentOutOfRangeException(nameof(senderState));
            if (responseBody != null && responseBody.Length != 3)
                throw new ArgumentException("Requires one exact three-byte constructed body, or null if unavailable.", nameof(responseBody));
            // Store a value representation, not the caller's mutable bytes.
            ResponseBodyHex = responseBody == null ? null : BitConverter.ToString(responseBody).Replace("-", "").ToLowerInvariant();
            SenderState = senderState;
            StackDelta = stackDelta;
            ModeledProgramStartAddress = modeledProgramStartAddress;
            ModeledProgramBytes = modeledProgramBytes;
        }
        public string? ResponseBodyHex { get; }
        public AL5ModeledSenderState SenderState { get; }
        public int? StackDelta { get; }
        public int? ModeledProgramStartAddress { get; }
        public int? ModeledProgramBytes { get; }
        public bool PhysicalDeliveryVerified => false;
    }

    public sealed class AL5LoaderModelDecision
    {
        private AL5LoaderModelDecision(AL5LoaderModelResult result, string expected, AL5OfflineOutcome outcome, AL5LoaderModelReplyReason reason)
        { Result = result; ExpectedResponseBodyHex = expected; Outcome = outcome; Reason = reason; }
        public AL5LoaderModelResult Result { get; }
        public string ExpectedResponseBodyHex { get; }
        public AL5OfflineOutcome Outcome { get; }
        public AL5LoaderModelReplyReason Reason { get; }

        internal static AL5LoaderModelDecision Assess(AL5OfflineOperation operation, AL5LoaderModelResult result)
        {
            string expected;
            switch (operation.Phase)
            {
                case AL5ProgrammingPhase.ConditionalErase: expected = "7600ee"; break;
                case AL5ProgrammingPhase.CalibrationBlocks:
                case AL5ProgrammingPhase.CollateralRestoration: expected = "760073"; break;
                case AL5ProgrammingPhase.Finalization: expected = "760086"; break;
                default: throw new InvalidOperationException("This stage has no captured-loader reply contract.");
            }
            AL5LoaderModelDecision Decision(AL5OfflineOutcome outcome, AL5LoaderModelReplyReason reason) =>
                new AL5LoaderModelDecision(result, expected, outcome, reason);
            if (result.SenderState == AL5ModeledSenderState.TimedOutWithSoftwareReentry)
                return Decision(AL5OfflineOutcome.ReplyLost, AL5LoaderModelReplyReason.SenderTimeout);
            if (result.SenderState == AL5ModeledSenderState.Unobserved)
                return Decision(AL5OfflineOutcome.UnconfirmedModelResult, AL5LoaderModelReplyReason.SenderUnobserved);
            string? body = result.ResponseBodyHex;
            if (body == null)
                return Decision(AL5OfflineOutcome.UnconfirmedModelResult, AL5LoaderModelReplyReason.ReplyMissing);
            if (!body.StartsWith("7600", StringComparison.Ordinal))
                return Decision(AL5OfflineOutcome.ModelFailure, AL5LoaderModelReplyReason.MalformedReply);
            if (body == "7600f8" || body == "760085" || body == "760089" || body == "760077" || body == "7600ff")
                return Decision(AL5OfflineOutcome.ModelFailure, AL5LoaderModelReplyReason.NativeFailure);
            if (body != expected)
                return Decision(AL5OfflineOutcome.ModelFailure, AL5LoaderModelReplyReason.UnexpectedReply);
            if (!result.StackDelta.HasValue)
                return Decision(AL5OfflineOutcome.UnconfirmedModelResult, AL5LoaderModelReplyReason.StackUnknown);
            if (result.StackDelta != 0)
                return Decision(AL5OfflineOutcome.ModelFailure, AL5LoaderModelReplyReason.NonzeroStackDelta);
            if (operation.Phase == AL5ProgrammingPhase.CalibrationBlocks || operation.Phase == AL5ProgrammingPhase.CollateralRestoration)
            {
                if (!result.ModeledProgramStartAddress.HasValue || !result.ModeledProgramBytes.HasValue)
                    return Decision(AL5OfflineOutcome.UnconfirmedModelResult, AL5LoaderModelReplyReason.ProgramCoverageUnknown);
                if (result.ModeledProgramStartAddress != operation.StartAddress || result.ModeledProgramBytes != operation.Length)
                    return Decision(AL5OfflineOutcome.ModelFailure, AL5LoaderModelReplyReason.ProgramCoverageMismatch);
            }
            return Decision(AL5OfflineOutcome.ModelCompleted, AL5LoaderModelReplyReason.ExpectedReply);
        }
    }
}

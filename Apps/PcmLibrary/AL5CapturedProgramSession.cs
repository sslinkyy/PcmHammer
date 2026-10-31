// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    public enum AL5CapturedProgramState { AwaitingRequest, AwaitingReply, ChecksumRejected, Stopped, BlocksAcknowledged }

    /// <summary>Replays saved observations only. A reply is not physical readback or retry authority.</summary>
    public sealed class AL5CapturedProgramSession
    {
        private readonly AL5CapturedProgramImage image = new AL5CapturedProgramImage();
        private byte[]? pending;
        private int nextAddress = AL5CapturedProgramImage.StartAddress;
        public AL5CapturedProgramState State { get; private set; } = AL5CapturedProgramState.AwaitingRequest;
        public int PositiveReplies { get; private set; }
        public int ChecksumErrors { get; private set; }
        public int RepeatsAfterChecksumError { get; private set; }
        public int RepeatsWithoutReply { get; private set; }
        public bool LiveWriteEnabled => false;
        public bool AutomaticRetryEnabled => false;
        public bool PhysicalReadbackVerified => false;

        public void ObserveRequest(byte[] request)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));
            if(request.Length<14 || request.Length>524) throw new ArgumentException("Unbounded request.");
            request=(byte[])request.Clone();
            if (State == AL5CapturedProgramState.Stopped || State == AL5CapturedProgramState.BlocksAcknowledged)
                throw new InvalidOperationException("Captured attempt is closed.");
            if (pending != null)
            {
                if (pending.Length != request.Length) throw new ArgumentException("Pending request changed.");
                for (int i=0;i<request.Length;i++)
                    if (pending[i]!=request[i]) throw new ArgumentException("Pending request changed.");
                if (State == AL5CapturedProgramState.ChecksumRejected) RepeatsAfterChecksumError++;
                else RepeatsWithoutReply++;
            }
            else
            {
                // Validate packet and immutable ownership at the existing capture boundary.
                var validated = new AL5CapturedProgramImage(); validated.Observe(request);
                int address=(request[7]<<16)|(request[8]<<8)|request[9];
                int count=request.Length-12;
                if (address!=nextAddress || count!=Math.Min(512,AL5CapturedProgramImage.EndAddressExclusive-nextAddress))
                    throw new ArgumentException("Expected the next contiguous captured block.");
                pending=(byte[])request.Clone();
            }
            State=AL5CapturedProgramState.AwaitingReply;
        }

        public void ObserveReply(byte[] body)
        {
            if (body == null) throw new ArgumentNullException(nameof(body));
            if (body.Length!=3 || body[0]!=0x76 || body[1]!=0)
                throw new ArgumentException("Expected an exact loader reply body.");
            if (State!=AL5CapturedProgramState.AwaitingReply || pending==null)
                throw new InvalidOperationException("No single pending request can own this reply.");
            if (body[2]==0x77) { ChecksumErrors++; State=AL5CapturedProgramState.ChecksumRejected; return; }
            if (body[2]!=0x73) { State=AL5CapturedProgramState.Stopped; return; }
            image.Observe(pending);
            nextAddress+=pending.Length-12; pending=null; PositiveReplies++;
            State=image.Complete ? AL5CapturedProgramState.BlocksAcknowledged : AL5CapturedProgramState.AwaitingRequest;
        }

        public byte[] CopyAcknowledgedCapture()
        {
            if(State!=AL5CapturedProgramState.BlocksAcknowledged)
                throw new InvalidOperationException("Captured block sequence is incomplete.");
            return image.CopyCompleteImage();
        }

        public AL5ProgrammingAssessment AssessReference(byte[] calibration, byte[] collateral)
        {
            if(State!=AL5CapturedProgramState.BlocksAcknowledged)
                throw new InvalidOperationException("Incomplete captured block sequence.");
            return image.AssessReference(calibration,collateral);
        }
    }
}

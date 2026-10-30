// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    /// <summary>
    /// Context supplied by the caller, not inferred from an RX header or payload.
    /// The caller must establish VPW/request context independently. Selecting it
    /// for an offline experiment does not establish request/reply correlation.
    /// </summary>
    public enum AutoCalVpwRequestContext
    {
        Unspecified = 0,
        ExplicitVpwRequest8A00Context = 1
    }

    public enum AutoCalVpwProjectionKind
    {
        UnsupportedContext,
        InvalidOuterCrc,
        UnsupportedReceivePayloadLength,
        TransmitCommandMismatch,
        TransmitCommand,
        ReceivePayload,
        MalformedCommandError,
        ErrorCommandMismatch,
        CommandError
    }

    /// <summary>
    /// Offline field projection of a complete AutoCal host envelope under one
    /// explicit VPW command context. This is not a physical VPW frame decoder,
    /// transport, message matcher, or programming capability.
    /// See Docs/AL5/AUTOCAL_VPW_TRANSPORT_STATIC.json for field provenance.
    /// </summary>
    public sealed class AutoCalVpwEnvelope
    {
        private readonly AutoCalHostFrame frame;
        private byte[]? receiveOpaqueHeader;
        private byte[]? errorRemainder;

        private AutoCalVpwEnvelope(AutoCalHostFrame frame, AutoCalVpwRequestContext context)
        {
            this.frame = frame;
            Context = context;
        }

        public AutoCalVpwRequestContext Context { get; }
        public AutoCalVpwProjectionKind Kind { get; private set; }
        public AutoCalHostDirection HostDirection => frame.Direction;
        public bool OuterCrcMatches => frame.CrcMatches;
        public byte[] RawFrame => frame.RawBytes;
        public byte[] RawPayload => frame.Payload;

        /// <summary>
        /// Exact host payload only for a supported, CRC-valid normal layout.
        /// No VPW CRC is added/removed, no prefix is stripped, and no physical
        /// sender, bus speed, timestamp or successful execution is inferred.
        /// </summary>
        public byte[]? HostBusPayload => Kind == AutoCalVpwProjectionKind.TransmitCommand
            || Kind == AutoCalVpwProjectionKind.ReceivePayload ? frame.Payload : null;

        public ushort? TransmitCommandWord { get; private set; }
        public byte? TransmitSelectorByte { get; private set; }
        public byte? TransmitReservedByte { get; private set; }
        public uint? TransmitCallerMetadata { get; private set; }

        /// <summary>
        /// Header bytes 2..5 under the supplied 8A00 receive context. This is not
        /// a route ID, ACK, exception status or boolean success indication.
        /// Null on the distinct command-error path and rejected projections.
        /// </summary>
        public uint? ReceiveReturnedMetadata { get; private set; }
        public byte[]? ReceiveOpaqueHeader6To9 => receiveOpaqueHeader == null
            ? null : (byte[])receiveOpaqueHeader.Clone();

        public ushort? ErrorEchoedCommand { get; private set; }
        public bool? ErrorEchoMatchesRequestedCommand { get; private set; }

        /// <summary>Exposed only after the error command echo matches 8A00.</summary>
        public ushort? ExceptionStatus { get; private set; }
        public byte[]? ErrorTrailingPayload => errorRemainder == null
            ? null : (byte[])errorRemainder.Clone();

        public static AutoCalVpwEnvelope Project(AutoCalHostFrame frame, AutoCalVpwRequestContext context)
        {
            if (frame == null) throw new ArgumentNullException(nameof(frame));
            var result = new AutoCalVpwEnvelope(frame, context);
            if (context != AutoCalVpwRequestContext.ExplicitVpwRequest8A00Context)
            {
                result.Kind = AutoCalVpwProjectionKind.UnsupportedContext;
                return result;
            }
            if (!frame.CrcMatches)
            {
                result.Kind = AutoCalVpwProjectionKind.InvalidOuterCrc;
                return result;
            }

            byte[] header = frame.OpaqueHeaderBytes; // Original offsets 2..9.
            if (frame.Direction == AutoCalHostDirection.HostToDevice)
            {
                result.TransmitCommandWord = Read16(header, 0);
                result.TransmitSelectorByte = header[2];
                result.TransmitReservedByte = header[3];
                result.TransmitCallerMetadata = Read32(header, 4);
                result.Kind = result.TransmitCommandWord == 0x8A00
                    ? AutoCalVpwProjectionKind.TransmitCommand
                    : AutoCalVpwProjectionKind.TransmitCommandMismatch;
                return result;
            }

            // This bound is established for HAPI receive, not the TX producer.
            if (frame.PayloadLength > 0xC000)
            {
                result.Kind = AutoCalVpwProjectionKind.UnsupportedReceivePayloadLength;
                return result;
            }
            result.receiveOpaqueHeader = new byte[4];
            Array.Copy(header, 4, result.receiveOpaqueHeader, 0, 4);
            if (Read16(header, 0) != 0xFF00)
            {
                result.ReceiveReturnedMetadata = Read32(header, 0);
                result.Kind = AutoCalVpwProjectionKind.ReceivePayload;
                return result;
            }

            byte[] payload = frame.Payload;
            if (payload.Length < 4)
            {
                result.Kind = AutoCalVpwProjectionKind.MalformedCommandError;
                return result;
            }
            result.ErrorEchoedCommand = Read16(payload, 0);
            result.ErrorEchoMatchesRequestedCommand = result.ErrorEchoedCommand == 0x8A00;
            result.errorRemainder = new byte[payload.Length - 4];
            Array.Copy(payload, 4, result.errorRemainder, 0, result.errorRemainder.Length);
            if (result.ErrorEchoMatchesRequestedCommand != true)
            {
                result.Kind = AutoCalVpwProjectionKind.ErrorCommandMismatch;
                return result;
            }
            result.ExceptionStatus = Read16(payload, 2);
            result.Kind = AutoCalVpwProjectionKind.CommandError;
            return result;
        }

        private static ushort Read16(byte[] bytes, int start)
            => (ushort)(bytes[start] | bytes[start + 1] << 8);
        private static uint Read32(byte[] bytes, int start)
            => (uint)(bytes[start] | bytes[start + 1] << 8 | bytes[start + 2] << 16 | bytes[start + 3] << 24);
    }
}

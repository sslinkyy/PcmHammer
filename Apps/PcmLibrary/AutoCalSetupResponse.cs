// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    /// <summary>Explicit caller context; never inferred from a received frame.</summary>
    public enum AutoCalSetupCommandContext
    {
        Unspecified = 0,
        Command8603 = 0x8603,
        Command8604 = 0x8604,
        Command8800 = 0x8800,
        Command8B01 = 0x8B01
    }

    public enum AutoCalSetupResponseKind
    {
        UnsupportedContext,
        UnsupportedDirection,
        InvalidOuterCrc,
        UnsupportedReceivePayloadLength,
        ResponseCommandMismatch,
        EchoedCommandResponse,
        MalformedCommandError,
        ErrorCommandMismatch,
        CommandError
    }

    /// <summary>
    /// File-only interpretation of the ordinary echoed-command receive path
    /// for four traced AutoCal setup commands. This does not implement a
    /// transport, request correlation, firmware status decoder or bus setup.
    /// See Docs/AL5/AUTOCAL_SETUP_RESPONSES_STATIC.json for provenance.
    /// </summary>
    public sealed class AutoCalSetupResponse
    {
        private readonly AutoCalHostFrame frame;
        private byte[]? opaqueHeader;
        private byte[]? errorRemainder;

        private AutoCalSetupResponse(AutoCalHostFrame frame, AutoCalSetupCommandContext context)
        {
            this.frame = frame;
            Context = context;
        }

        public AutoCalSetupCommandContext Context { get; }
        public AutoCalSetupResponseKind Kind { get; private set; }
        public AutoCalHostDirection HostDirection => frame.Direction;
        public bool OuterCrcMatches => frame.CrcMatches;
        public byte[] RawFrame => frame.RawBytes;
        public byte[] RawPayload => frame.Payload;
        public ushort? ReceivedCommandWord { get; private set; }
        public byte[]? OpaqueHeader4To9 => opaqueHeader == null ? null : (byte[])opaqueHeader.Clone();

        /// <summary>
        /// Exact payload of a CRC-valid, matching normal reply. Empty is valid;
        /// byte 01 has no inferred success meaning. Unknown bytes are retained.
        /// Null for errors or rejected projections.
        /// </summary>
        public byte[]? ReplyPayload => Kind == AutoCalSetupResponseKind.EchoedCommandResponse
            ? frame.Payload : null;

        /// <summary>
        /// Declared and complete received payload extent, including zero. The
        /// native callback returns this length, not a decoded status byte.
        /// Never substitutes the length of a previous request buffer.
        /// </summary>
        public int? ReturnedPayloadLength => Kind == AutoCalSetupResponseKind.EchoedCommandResponse
            ? (int?)frame.PayloadLength : null;

        public ushort? ErrorEchoedCommand { get; private set; }
        public bool? ErrorEchoMatchesRequestedCommand { get; private set; }

        /// <summary>
        /// Error status exposed only after the error command echo matches.
        /// A zero status does not turn a command-error envelope into a reply.
        /// </summary>
        public ushort? ExceptionStatus { get; private set; }
        public byte[]? ErrorTrailingPayload => errorRemainder == null ? null : (byte[])errorRemainder.Clone();

        public static AutoCalSetupResponse Project(AutoCalHostFrame frame, AutoCalSetupCommandContext context)
        {
            if (frame == null) throw new ArgumentNullException(nameof(frame));
            var result = new AutoCalSetupResponse(frame, context);
            if (context != AutoCalSetupCommandContext.Command8603
                && context != AutoCalSetupCommandContext.Command8604
                && context != AutoCalSetupCommandContext.Command8800
                && context != AutoCalSetupCommandContext.Command8B01)
            {
                result.Kind = AutoCalSetupResponseKind.UnsupportedContext;
                return result;
            }
            if (frame.Direction != AutoCalHostDirection.DeviceToHost)
            {
                result.Kind = AutoCalSetupResponseKind.UnsupportedDirection;
                return result;
            }
            if (!frame.CrcMatches)
            {
                result.Kind = AutoCalSetupResponseKind.InvalidOuterCrc;
                return result;
            }
            if (frame.PayloadLength > 0xC000)
            {
                result.Kind = AutoCalSetupResponseKind.UnsupportedReceivePayloadLength;
                return result;
            }

            byte[] header = frame.OpaqueHeaderBytes; // Original offsets 2..9.
            result.ReceivedCommandWord = Read16(header, 0);
            result.opaqueHeader = new byte[6];
            Array.Copy(header, 2, result.opaqueHeader, 0, 6);
            if (result.ReceivedCommandWord != 0xFF00)
            {
                result.Kind = result.ReceivedCommandWord == (ushort)context
                    ? AutoCalSetupResponseKind.EchoedCommandResponse
                    : AutoCalSetupResponseKind.ResponseCommandMismatch;
                return result;
            }

            byte[] payload = frame.Payload;
            if (payload.Length < 4)
            {
                result.Kind = AutoCalSetupResponseKind.MalformedCommandError;
                return result;
            }
            result.ErrorEchoedCommand = Read16(payload, 0);
            result.ErrorEchoMatchesRequestedCommand = result.ErrorEchoedCommand == (ushort)context;
            result.errorRemainder = new byte[payload.Length - 4];
            Array.Copy(payload, 4, result.errorRemainder, 0, result.errorRemainder.Length);
            if (result.ErrorEchoMatchesRequestedCommand != true)
            {
                result.Kind = AutoCalSetupResponseKind.ErrorCommandMismatch;
                return result;
            }
            result.ExceptionStatus = Read16(payload, 2);
            result.Kind = AutoCalSetupResponseKind.CommandError;
            return result;
        }

        private static ushort Read16(byte[] bytes, int start)
            => (ushort)(bytes[start] | bytes[start + 1] << 8);
    }
}

// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace PcmHacking
{
    public enum AutoCalHostDirection { HostToDevice, DeviceToHost }

    /// <summary>
    /// One complete, long-header AutoCal host-interface frame.
    /// The caller establishes the direction and complete-frame boundary from its
    /// source evidence. This decoder does not parse HTX containers or USB streams.
    /// Header bytes 2 through 9 and the RX trailing byte remain uninterpreted.
    /// </summary>
    public sealed class AutoCalHostFrame
    {
        private readonly byte[] rawBytes;

        private AutoCalHostFrame(byte[] source, AutoCalHostDirection direction, int payloadLength)
        {
            rawBytes = (byte[])source.Clone();
            Direction = direction;
            PayloadLength = payloadLength;
            int crcOffset = 12 + payloadLength;
            StoredCrc = (ushort)(rawBytes[crcOffset] | rawBytes[crcOffset + 1] << 8);
            ComputedCrc = ComputeCrc(rawBytes, crcOffset);
            RxTrailingByte = direction == AutoCalHostDirection.DeviceToHost
                ? (byte?)rawBytes[crcOffset + 2] : null;
        }

        public AutoCalHostDirection Direction { get; }
        public int PayloadLength { get; }
        public ushort StoredCrc { get; }
        public ushort ComputedCrc { get; }
        public bool CrcMatches => StoredCrc == ComputedCrc;

        /// <summary>Observed RX frames end in 0x19; other values are preserved, not assigned meaning.</summary>
        public byte? RxTrailingByte { get; }

        /// <summary>Exact source bytes, including an invalid checksum when present.</summary>
        public byte[] RawBytes => (byte[])rawBytes.Clone();

        /// <summary>Uninterpreted header bytes at offsets 2 through 9.</summary>
        public byte[] OpaqueHeaderBytes => CopyBytes(2, 8);

        public byte[] Payload => CopyBytes(12, PayloadLength);

        /// <summary>
        /// Encode the traced long-header host-to-device layout. Explicit fields
        /// preserve caller choices; this does not establish command support or
        /// physical transmission. No VPW CRC is inserted into the payload.
        /// </summary>
        public static byte[] EncodeLongHeader(ushort command, byte selector, uint callerMetadata, byte[] payload)
        {
            if (payload == null) throw new ArgumentNullException(nameof(payload));
            if (payload.Length > ushort.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(payload), "The host header has a 16-bit payload length.");
            var result = new byte[payload.Length + 14];
            result[0] = 0x01;
            result[1] = 0x54;
            result[2] = (byte)command;
            result[3] = (byte)(command >> 8);
            result[4] = selector;
            result[5] = 0;
            for (int index = 0; index < 4; index++)
                result[6 + index] = (byte)(callerMetadata >> (8 * index));
            result[10] = (byte)payload.Length;
            result[11] = (byte)(payload.Length >> 8);
            Array.Copy(payload, 0, result, 12, payload.Length);
            ushort crc = ComputeCrc(result, result.Length - 2);
            result[result.Length - 2] = (byte)crc;
            result[result.Length - 1] = (byte)(crc >> 8);
            return result;
        }

        /// <summary>
        /// Decode one complete 12-byte-header frame. The caller must select
        /// this format explicitly: short 8-byte headers and USB packet/stream
        /// boundaries are unsupported. Framing failures throw; CRC mismatches are data.
        /// See Docs/AL5/AUTOCAL_TRANSPORT_STATIC.json for the static checksum evidence.
        /// </summary>
        public static AutoCalHostFrame ParseLongHeader(AutoCalHostDirection expectedDirection, byte[] source)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (expectedDirection != AutoCalHostDirection.HostToDevice && expectedDirection != AutoCalHostDirection.DeviceToHost)
                throw new ArgumentOutOfRangeException(nameof(expectedDirection), "An explicit host-interface direction is required.");
            if (source.Length < 12)
                throw new FormatException("A complete 12-byte header is required; short 8-byte headers are unsupported.");
            if (source[0] != 0x01 || (source[1] != 0x54 && source[1] != 0x52))
                throw new NotSupportedException("Only 01 54 TX and 01 52 RX long-header frames are supported.");

            var direction = source[1] == 0x54
                ? AutoCalHostDirection.HostToDevice : AutoCalHostDirection.DeviceToHost;
            if (expectedDirection != direction)
                throw new FormatException("The caller's direction disagrees with the host-interface frame prefix.");
            int payloadLength = source[10] | source[11] << 8;
            int expectedLength = payloadLength + (direction == AutoCalHostDirection.HostToDevice ? 14 : 15);
            if (source.Length != expectedLength)
                throw new FormatException("Frame length does not equal its declared payload plus the complete wrapper.");

            return new AutoCalHostFrame(source, direction, payloadLength);
        }

        private byte[] CopyBytes(int offset, int count)
        {
            byte[] result = new byte[count];
            Array.Copy(rawBytes, offset, result, 0, count);
            return result;
        }

        private static ushort ComputeCrc(byte[] bytes, int count)
        {
            // Hapi's table at 0xAD2CE4 matches all 256 reflected 0xA001 entries.
            // Initial value is zero; no final XOR; trailer word is little-endian.
            ushort crc = 0;
            for (int index = 0; index < count; index++)
            {
                crc ^= bytes[index];
                for (int bit = 0; bit < 8; bit++)
                    crc = (ushort)((crc & 1) != 0 ? (crc >> 1) ^ 0xA001 : crc >> 1);
            }
            return crc;
        }
    }
}

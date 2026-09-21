// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Text;

namespace PcmHacking
{
    /// <summary>
    /// Strict read-only parser for iMob Racing Custom MultiMap metadata header generation 1.
    ///
    /// Parsing this header must never alter normal PCM-type detection, native OSID handling,
    /// kernel selection, flash write behavior, or recovery behavior.
    /// </summary>
    public static class ImobCustomOsMetadataParser
    {
        public const int HeaderAddress = 0x5F000;
        public const int HeaderSizeV1 = 0x100;

        private static readonly byte[] Signature = Encoding.ASCII.GetBytes("IMOBMM01");

        private sealed class Region
        {
            public string Name;
            public uint Start;
            public uint Length;

            public Region(string name, uint start, uint length)
            {
                this.Name = name;
                this.Start = start;
                this.Length = length;
            }
        }

        public static CustomOsMetadataStatus Parse(
            byte[] image,
            out CustomOsMetadata metadata,
            out string error)
        {
            metadata = null;
            error = string.Empty;

            if (image == null || image.Length < HeaderAddress + Signature.Length)
            {
                return CustomOsMetadataStatus.NotPresent;
            }

            for (int i = 0; i < Signature.Length; i++)
            {
                if (image[HeaderAddress + i] != Signature[i])
                {
                    return CustomOsMetadataStatus.NotPresent;
                }
            }

            if (image.Length < HeaderAddress + HeaderSizeV1)
            {
                error = "IMOBMM01 header is truncated.";
                return CustomOsMetadataStatus.Invalid;
            }

            ushort major = ReadU16(image, HeaderAddress + 0x08);
            ushort minor = ReadU16(image, HeaderAddress + 0x0A);
            uint headerSize = ReadU32(image, HeaderAddress + 0x0C);

            if (major != 1)
            {
                error = string.Format(
                    "Unsupported IMOBMM header major version {0}.",
                    major);
                return CustomOsMetadataStatus.Unsupported;
            }

            if (headerSize != HeaderSizeV1)
            {
                error = string.Format(
                    "Unsupported IMOBMM01 header size 0x{0:X}.",
                    headerSize);
                return CustomOsMetadataStatus.Unsupported;
            }

            if (ReadU32(image, HeaderAddress + 0x10) != 0x12345678)
            {
                error = "IMOBMM01 endian marker is invalid.";
                return CustomOsMetadataStatus.Invalid;
            }

            uint storedCrc = ReadU32(image, HeaderAddress + 0x74);
            byte[] header = new byte[HeaderSizeV1];
            Buffer.BlockCopy(image, HeaderAddress, header, 0, HeaderSizeV1);
            header[0x74] = 0;
            header[0x75] = 0;
            header[0x76] = 0;
            header[0x77] = 0;

            uint computedCrc = ComputeCrc32(header);
            if (computedCrc != storedCrc)
            {
                error = string.Format(
                    "IMOBMM01 header CRC mismatch: stored 0x{0:X8}, computed 0x{1:X8}.",
                    storedCrc,
                    computedCrc);
                return CustomOsMetadataStatus.Invalid;
            }

            CustomOsMetadata result = new CustomOsMetadata
            {
                FormatSignature = "IMOBMM01",
                HeaderFormatMajor = major,
                HeaderFormatMinor = minor,
                HeaderSize = headerSize,

                BaseOs = ReadU32(image, HeaderAddress + 0x14),
                CustomOsId = ReadU32(image, HeaderAddress + 0x18),

                ProductMajor = ReadU16(image, HeaderAddress + 0x1C),
                ProductMinor = ReadU16(image, HeaderAddress + 0x1E),
                ProductPatch = ReadU16(image, HeaderAddress + 0x20),

                LayoutVersion = ReadU16(image, HeaderAddress + 0x22),
                SecurityVersion = ReadU16(image, HeaderAddress + 0x24),

                BuildNumber = ReadU32(image, HeaderAddress + 0x28),
                FeatureFlags = ReadU32(image, HeaderAddress + 0x2C),
                BuildFlags = ReadU32(image, HeaderAddress + 0x30),

                CustomRegionStart = ReadU32(image, HeaderAddress + 0x34),
                CustomRegionLength = ReadU32(image, HeaderAddress + 0x38),
                CodeStart = ReadU32(image, HeaderAddress + 0x3C),
                CodeLength = ReadU32(image, HeaderAddress + 0x40),

                Map1Start = ReadU32(image, HeaderAddress + 0x44),
                Map1Length = ReadU32(image, HeaderAddress + 0x48),
                Map2Start = ReadU32(image, HeaderAddress + 0x4C),
                Map2Length = ReadU32(image, HeaderAddress + 0x50),
                Map3Start = ReadU32(image, HeaderAddress + 0x54),
                Map3Length = ReadU32(image, HeaderAddress + 0x58),
                Map4Start = ReadU32(image, HeaderAddress + 0x5C),
                Map4Length = ReadU32(image, HeaderAddress + 0x60),

                ConfigStart = ReadU32(image, HeaderAddress + 0x64),
                ConfigLength = ReadU32(image, HeaderAddress + 0x68),
                ReserveStart = ReadU32(image, HeaderAddress + 0x6C),
                ReserveLength = ReadU32(image, HeaderAddress + 0x70),

                HeaderCrc32 = storedCrc,
                ConfigCrc32 = ReadU32(image, HeaderAddress + 0x78),

                ProductName = ReadFixedAscii(image, HeaderAddress + 0x80, 0x30),
                VersionString = ReadFixedAscii(image, HeaderAddress + 0xB0, 0x10),
                BuildLabel = ReadFixedAscii(image, HeaderAddress + 0xC0, 0x20),
            };

            if (!ValidateRegions(image.Length, result, out error))
            {
                return CustomOsMetadataStatus.Invalid;
            }

            metadata = result;
            return CustomOsMetadataStatus.Valid;
        }

        private static bool ValidateRegions(
            int imageLength,
            CustomOsMetadata metadata,
            out string error)
        {
            error = string.Empty;

            Region[] regions = new Region[]
            {
                new Region("custom", metadata.CustomRegionStart, metadata.CustomRegionLength),
                new Region("code", metadata.CodeStart, metadata.CodeLength),
                new Region("map1", metadata.Map1Start, metadata.Map1Length),
                new Region("map2", metadata.Map2Start, metadata.Map2Length),
                new Region("map3", metadata.Map3Start, metadata.Map3Length),
                new Region("map4", metadata.Map4Start, metadata.Map4Length),
                new Region("config", metadata.ConfigStart, metadata.ConfigLength),
                new Region("reserve", metadata.ReserveStart, metadata.ReserveLength),
            };

            for (int i = 0; i < regions.Length; i++)
            {
                ulong start = regions[i].Start;
                ulong length = regions[i].Length;
                ulong end = start + length;

                if (length == 0)
                {
                    error = string.Format(
                        "IMOBMM01 region '{0}' has zero length.",
                        regions[i].Name);
                    return false;
                }

                if (end > (ulong)imageLength || end < start)
                {
                    error = string.Format(
                        "IMOBMM01 region '{0}' is outside the image: start 0x{1:X}, length 0x{2:X}.",
                        regions[i].Name,
                        start,
                        length);
                    return false;
                }
            }

            ulong customStart = metadata.CustomRegionStart;
            ulong customEnd = customStart + metadata.CustomRegionLength;

            // All child regions must fit inside the declared custom region.
            for (int i = 1; i < regions.Length; i++)
            {
                ulong start = regions[i].Start;
                ulong end = start + regions[i].Length;

                if (start < customStart || end > customEnd)
                {
                    error = string.Format(
                        "IMOBMM01 region '{0}' is outside the declared custom region.",
                        regions[i].Name);
                    return false;
                }
            }

            // Child regions may not overlap one another.
            for (int i = 1; i < regions.Length; i++)
            {
                ulong aStart = regions[i].Start;
                ulong aEnd = aStart + regions[i].Length;

                for (int j = i + 1; j < regions.Length; j++)
                {
                    ulong bStart = regions[j].Start;
                    ulong bEnd = bStart + regions[j].Length;

                    if (aStart < bEnd && bStart < aEnd)
                    {
                        error = string.Format(
                            "IMOBMM01 regions '{0}' and '{1}' overlap.",
                            regions[i].Name,
                            regions[j].Name);
                        return false;
                    }
                }
            }

            return true;
        }

        private static ushort ReadU16(byte[] data, int offset)
        {
            return (ushort)((data[offset] << 8) | data[offset + 1]);
        }

        private static uint ReadU32(byte[] data, int offset)
        {
            return
                ((uint)data[offset] << 24) |
                ((uint)data[offset + 1] << 16) |
                ((uint)data[offset + 2] << 8) |
                data[offset + 3];
        }

        private static string ReadFixedAscii(byte[] data, int offset, int length)
        {
            int count = 0;
            while (count < length && data[offset + count] != 0)
            {
                count++;
            }

            return Encoding.ASCII.GetString(data, offset, count);
        }

        private static uint ComputeCrc32(byte[] data)
        {
            uint crc = 0xFFFFFFFF;

            for (int i = 0; i < data.Length; i++)
            {
                crc ^= data[i];

                for (int bit = 0; bit < 8; bit++)
                {
                    uint mask = (uint)-(int)(crc & 1);
                    crc = (crc >> 1) ^ (0xEDB88320 & mask);
                }
            }

            return ~crc;
        }
    }
}

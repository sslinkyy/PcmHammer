// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PcmHacking;

namespace Tests
{
    [TestClass]
    public class ImobCustomOsMetadataTests
    {
        [TestMethod]
        public void NoSignature_IsNotPresent()
        {
            byte[] image = new byte[512 * 1024];

            CustomOsMetadata metadata;
            string error;
            CustomOsMetadataStatus status =
                ImobCustomOsMetadataParser.Parse(
                    image,
                    out metadata,
                    out error);

            Assert.AreEqual(CustomOsMetadataStatus.NotPresent, status);
            Assert.IsNull(metadata);
        }

        [TestMethod]
        public void MetadataProbeHeader_Parses()
        {
            byte[] image = BuildValidHeaderImage();

            CustomOsMetadata metadata;
            string error;
            CustomOsMetadataStatus status =
                ImobCustomOsMetadataParser.Parse(
                    image,
                    out metadata,
                    out error);

            Assert.AreEqual(CustomOsMetadataStatus.Valid, status, error);
            Assert.IsNotNull(metadata);
            Assert.AreEqual("IMOBMM01", metadata.FormatSignature);
            Assert.AreEqual((uint)15189044, metadata.BaseOs);
            Assert.AreEqual((uint)0, metadata.CustomOsId);
            Assert.AreEqual((ushort)1, metadata.LayoutVersion);
            Assert.AreEqual((ushort)0, metadata.SecurityVersion);
            Assert.AreEqual((uint)1, metadata.BuildNumber);
            Assert.AreEqual("iMob Racing Custom MultiMap", metadata.ProductName);
            Assert.AreEqual("V0.0.1-META", metadata.VersionString);
            Assert.AreEqual((uint)0x5F000, metadata.CustomRegionStart);
            Assert.AreEqual((uint)0x11000, metadata.CustomRegionLength);
            Assert.AreEqual((uint)0xD4293458, metadata.HeaderCrc32);
        }

        [TestMethod]
        public void FileValidator_ExposesMetadataWithoutChangingE54Detection()
        {
            byte[] image = BuildValidHeaderImage();

            // E54 content markers used by Release/2.0.0 detection.
            image[0x1FFFE] = 0x4A;
            image[0x1FFFF] = 0xFC;
            image[0x7FFFE] = 0x4A;
            image[0x7FFFF] = 0xFC;
            image[0x20004] = 0x00;
            image[0x20005] = 0xE7;
            image[0x20006] = 0xC7;
            image[0x20007] = 0x34; // arbitrary nonzero OSID for structural test

            FileValidator validator =
                new FileValidator(image, new MockLogger(), PcmType.E54);

            Assert.AreEqual(PcmType.E54, validator.GetFileType());

            CustomOsMetadata metadata;
            string error;
            CustomOsMetadataStatus status =
                validator.GetCustomOsMetadata(
                    out metadata,
                    out error);

            Assert.AreEqual(CustomOsMetadataStatus.Valid, status, error);
            Assert.AreEqual((uint)15189044, metadata.BaseOs);
        }

        [TestMethod]
        public void BadCrc_IsInvalid()
        {
            byte[] image = BuildValidHeaderImage();
            image[ImobCustomOsMetadataParser.HeaderAddress + 0xC0] ^= 1;

            CustomOsMetadata metadata;
            string error;
            CustomOsMetadataStatus status =
                ImobCustomOsMetadataParser.Parse(
                    image,
                    out metadata,
                    out error);

            Assert.AreEqual(CustomOsMetadataStatus.Invalid, status);
            StringAssert.Contains(error, "CRC");
        }

        [TestMethod]
        public void UnknownMajor_IsUnsupported()
        {
            byte[] image = BuildValidHeaderImage();
            int h = ImobCustomOsMetadataParser.HeaderAddress;

            PutU16(image, h + 0x08, 2);
            RewriteCrc(image);

            CustomOsMetadata metadata;
            string error;
            CustomOsMetadataStatus status =
                ImobCustomOsMetadataParser.Parse(
                    image,
                    out metadata,
                    out error);

            Assert.AreEqual(CustomOsMetadataStatus.Unsupported, status);
        }

        [TestMethod]
        public void OutOfBoundsRegion_IsInvalid()
        {
            byte[] image = BuildValidHeaderImage();
            int h = ImobCustomOsMetadataParser.HeaderAddress;

            PutU32(image, h + 0x5C, 0x80000);
            RewriteCrc(image);

            CustomOsMetadata metadata;
            string error;
            CustomOsMetadataStatus status =
                ImobCustomOsMetadataParser.Parse(
                    image,
                    out metadata,
                    out error);

            Assert.AreEqual(CustomOsMetadataStatus.Invalid, status);
            StringAssert.Contains(error, "outside");
        }

        private static byte[] BuildValidHeaderImage()
        {
            byte[] image = new byte[512 * 1024];
            int h = ImobCustomOsMetadataParser.HeaderAddress;

            PutAscii(image, h + 0x00, 8, "IMOBMM01");
            PutU16(image, h + 0x08, 1);
            PutU16(image, h + 0x0A, 0);
            PutU32(image, h + 0x0C, 0x100);
            PutU32(image, h + 0x10, 0x12345678);
            PutU32(image, h + 0x14, 15189044);
            PutU32(image, h + 0x18, 0);

            PutU16(image, h + 0x1C, 0);
            PutU16(image, h + 0x1E, 0);
            PutU16(image, h + 0x20, 1);
            PutU16(image, h + 0x22, 1);
            PutU16(image, h + 0x24, 0);

            PutU32(image, h + 0x28, 1);
            PutU32(image, h + 0x2C, 0);
            PutU32(image, h + 0x30, 1);

            PutU32(image, h + 0x34, 0x5F000);
            PutU32(image, h + 0x38, 0x11000);
            PutU32(image, h + 0x3C, 0x5F100);
            PutU32(image, h + 0x40, 0x1F00);

            PutU32(image, h + 0x44, 0x61000);
            PutU32(image, h + 0x48, 0x3000);
            PutU32(image, h + 0x4C, 0x64000);
            PutU32(image, h + 0x50, 0x3000);
            PutU32(image, h + 0x54, 0x67000);
            PutU32(image, h + 0x58, 0x3000);
            PutU32(image, h + 0x5C, 0x6A000);
            PutU32(image, h + 0x60, 0x3000);

            PutU32(image, h + 0x64, 0x6D000);
            PutU32(image, h + 0x68, 0x1000);
            PutU32(image, h + 0x6C, 0x6E000);
            PutU32(image, h + 0x70, 0x2000);

            PutAscii(
                image,
                h + 0x80,
                0x30,
                "iMob Racing Custom MultiMap");

            PutAscii(
                image,
                h + 0xB0,
                0x10,
                "V0.0.1-META");

            PutAscii(
                image,
                h + 0xC0,
                0x20,
                "15189044 metadata probe");

            RewriteCrc(image);
            return image;
        }

        private static void RewriteCrc(byte[] image)
        {
            int h = ImobCustomOsMetadataParser.HeaderAddress;

            image[h + 0x74] = 0;
            image[h + 0x75] = 0;
            image[h + 0x76] = 0;
            image[h + 0x77] = 0;

            byte[] header = new byte[0x100];
            Buffer.BlockCopy(
                image,
                h,
                header,
                0,
                header.Length);

            PutU32(
                image,
                h + 0x74,
                ComputeCrc32(header));
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
                    crc =
                        (crc >> 1) ^
                        (0xEDB88320 & mask);
                }
            }

            return ~crc;
        }

        private static void PutU16(
            byte[] data,
            int offset,
            ushort value)
        {
            data[offset] = (byte)(value >> 8);
            data[offset + 1] = (byte)value;
        }

        private static void PutU32(
            byte[] data,
            int offset,
            uint value)
        {
            data[offset] = (byte)(value >> 24);
            data[offset + 1] = (byte)(value >> 16);
            data[offset + 2] = (byte)(value >> 8);
            data[offset + 3] = (byte)value;
        }

        private static void PutAscii(
            byte[] data,
            int offset,
            int length,
            string value)
        {
            byte[] raw = Encoding.ASCII.GetBytes(value);
            int count = Math.Min(raw.Length, length);
            Buffer.BlockCopy(raw, 0, data, offset, count);
        }
    }
}

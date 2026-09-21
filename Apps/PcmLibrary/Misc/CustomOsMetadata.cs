// SPDX-License-Identifier: GPL-3.0-only
namespace PcmHacking
{
    public enum CustomOsMetadataStatus
    {
        NotPresent = 0,
        Valid,
        Invalid,
        Unsupported,
    }

    /// <summary>
    /// Neutral description of custom-OS metadata embedded in a PCM image.
    /// This class deliberately contains no write/recovery behavior.
    /// </summary>
    public sealed class CustomOsMetadata
    {
        public string FormatSignature { get; internal set; } = string.Empty;
        public ushort HeaderFormatMajor { get; internal set; }
        public ushort HeaderFormatMinor { get; internal set; }
        public uint HeaderSize { get; internal set; }

        public uint BaseOs { get; internal set; }
        public uint CustomOsId { get; internal set; }

        public ushort ProductMajor { get; internal set; }
        public ushort ProductMinor { get; internal set; }
        public ushort ProductPatch { get; internal set; }

        public ushort LayoutVersion { get; internal set; }
        public ushort SecurityVersion { get; internal set; }

        public uint BuildNumber { get; internal set; }
        public uint FeatureFlags { get; internal set; }
        public uint BuildFlags { get; internal set; }

        public uint CustomRegionStart { get; internal set; }
        public uint CustomRegionLength { get; internal set; }
        public uint CodeStart { get; internal set; }
        public uint CodeLength { get; internal set; }

        public uint Map1Start { get; internal set; }
        public uint Map1Length { get; internal set; }
        public uint Map2Start { get; internal set; }
        public uint Map2Length { get; internal set; }
        public uint Map3Start { get; internal set; }
        public uint Map3Length { get; internal set; }
        public uint Map4Start { get; internal set; }
        public uint Map4Length { get; internal set; }

        public uint ConfigStart { get; internal set; }
        public uint ConfigLength { get; internal set; }
        public uint ReserveStart { get; internal set; }
        public uint ReserveLength { get; internal set; }

        public uint HeaderCrc32 { get; internal set; }
        public uint ConfigCrc32 { get; internal set; }

        public string ProductName { get; internal set; } = string.Empty;
        public string VersionString { get; internal set; } = string.Empty;
        public string BuildLabel { get; internal set; } = string.Empty;

        public string DisplayVersion
        {
            get
            {
                if (!string.IsNullOrEmpty(this.VersionString))
                {
                    return this.VersionString;
                }

                return string.Format(
                    "V{0}.{1}.{2}",
                    this.ProductMajor,
                    this.ProductMinor,
                    this.ProductPatch);
            }
        }
    }
}

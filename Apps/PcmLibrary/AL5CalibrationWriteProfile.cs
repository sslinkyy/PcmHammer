// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Security.Cryptography;

namespace PcmHacking
{
    /// <summary>Saved-byte compatibility only; it never identifies an attached controller.</summary>
    public sealed class AL5SavedWriteProfileAssessment
    {
        internal AL5SavedWriteProfileAssessment(string? boot,string? os,bool baselineSelector,bool candidateSelector,bool baselineValid,bool candidateValid)
        {BootSha256=boot;OsSha256=os;BaselineSelectorSupported=baselineSelector;CandidateSelectorSupported=candidateSelector;BaselineCalibrationChecksPass=baselineValid;CandidateChecksPass=candidateValid;}
        public string? BootSha256 { get; }
        public string? OsSha256 { get; }
        public bool BaselineSelectorSupported { get; }
        public bool CandidateSelectorSupported { get; }
        public bool CandidateChecksPass { get; }
        public bool BaselineCalibrationChecksPass { get; }
        public bool BootMatches => BootSha256==AL5CalibrationWriteProfile.SupportedBootSha256;
        public bool OsMatches => OsSha256==AL5CalibrationWriteProfile.SupportedOsSha256;
        public bool SavedBytesMatchProfile => BootMatches && OsMatches && BaselineSelectorSupported && CandidateSelectorSupported && BaselineCalibrationChecksPass && CandidateChecksPass;
        public bool LiveControllerIdentityVerified => false;
        public bool LiveSecurityAuthorizationVerified => false;
        public bool LiveWriteEnabled => false;
    }

    public static class AL5CalibrationWriteProfile
    {
        public const string SupportedBootSha256="e835d7a7d50d07d976d6562619545861b688a781d4dda9837f7e36e71bf568c6";
        public const string SupportedOsSha256="145d0dde8c4de88e3145b5693685ab28958d1dda70743c589cc0c7deaa4b45e7";
        public const int OsStart=0x20000,OsLength=679828,SecuritySelectorAddress=0x10954;
        // These are observations from the fingerprinted selector-zero profile,
        // not a generic algorithm, current-session seed or an authorized key sender.
        public const ushort SavedSelectorZeroSeed=0x9CE5,SavedSelectorZeroKey=0xBC08;
        private static string Hash(byte[] bytes,int start,int count)
        {using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(bytes,start,count)).Replace("-","").ToLowerInvariant();}
        /// <summary>Reject recognized AL5 full images from generic PCM writing, even with damaged calibration.</summary>
        public static bool ContainsKnownAl5FlashCode(byte[] image)
        {
            if(image==null)throw new ArgumentNullException(nameof(image));
            if(image.Length!=0x100000)return false;
            return Hash(image,0,0x4000)==SupportedBootSha256 || Hash(image,OsStart,OsLength)==SupportedOsSha256;
        }
        public static AL5SavedWriteProfileAssessment InspectSavedReference(byte[] fullReference,byte[] candidate)
        {
            if(fullReference==null || candidate==null)throw new ArgumentNullException();
            bool full=fullReference.Length==0x100000,cal=candidate.Length==AL5CalibrationInspection.Length;
            byte[]? reference=full?(byte[])fullReference.Clone():null,edited=cal?(byte[])candidate.Clone():null;
            var baselineCalibration=new byte[full?AL5CalibrationInspection.Length:0];
            if(full)Buffer.BlockCopy(reference!,AL5CalibrationInspection.StartAddress,baselineCalibration,0,baselineCalibration.Length);
            return new AL5SavedWriteProfileAssessment(full?Hash(reference!,0,0x4000):null,
                full?Hash(reference!,OsStart,OsLength):null,
                full && reference![SecuritySelectorAddress]==0,
                cal && edited![SecuritySelectorAddress-AL5CalibrationInspection.StartAddress]==0,
                full && AL5CalibrationInspection.Inspect(baselineCalibration).ChecksPass,
                cal && AL5CalibrationInspection.Inspect(edited!).ChecksPass);
        }
    }
}

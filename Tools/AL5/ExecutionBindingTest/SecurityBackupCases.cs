using PcmHacking;
using System.Security.Cryptography;

static partial class Program
{
    static byte[] Hex(string s)=>Convert.FromHexString(s);
    static AL5SavedSecurityExchange SeededSecurity()
    {
        var security=new AL5SavedSecurityExchange(original);
        security.ObserveSavedSeedRequestAccepted(Hex("6c18f02701"));
        security.ObserveSavedSeedReply(Hex("6cf01867019ce5"));
        Check(security.State==AL5SavedSecurityState.KeyReviewRequired,"fresh saved seed owns review");return security;
    }
    static byte[] ReadReply(byte[] request,byte[] image)
    {
        int address=(request[20]<<16)|(request[21]<<8)|request[22],count=request[23];
        var payload=new byte[22+count];Array.Copy(request,4,payload,0,20);payload[0]=0x61;payload[1]=0x72;payload[3]=0;
        image.AsSpan(address,count).CopyTo(payload.AsSpan(20,count));AL5ReadOnlyCoreSession.SetCrc(payload);
        var reply=new byte[4+payload.Length];Hex("6df018f1").CopyTo(reply,0);payload.CopyTo(reply,4);return reply;
    }
    static AL5SavedBackupPath AcquireOriginal(byte[] image,string id)
    {
        var path=new AL5SavedBackupPath(id,Hex("0102030405060708"),Hex("0807060504030201"));
        Reject(()=>path.RecordEntryBoundaryForOfflineReview());Reject(()=>path.CopyOriginalImage());
        while(path.OriginalBytesObserved<0x100000)
        {
            byte[] request=path.BeginNextSavedRequest();
            Check(path.ObserveSavedReply(ReadReply(request,image))==AL5ReadOnlyCoreReply.Matched,"original full-address correlated read");
        }
        Check(path.CopyOriginalImage().SequenceEqual(image),"original complete coverage without padding");return path;
    }
    static void AcquirePrepared(AL5SavedBackupPath path,byte[] image)
    {
        path.RecordEntryBoundaryForOfflineReview();
        Reject(()=>path.RecordEntryBoundaryForOfflineReview());Reject(()=>path.CopyPreparedReference());
        bool first=true;
        while(path.Phase!=AL5SavedBackupPhase.Complete)
        {
            byte[] request=path.BeginNextSavedRequest();byte[] reply=ReadReply(request,image);
            if(first)
            {
                // Correct address/count/sequence but another epoch's nonce, with a valid CRC.
                var stale=(byte[])reply.Clone();stale[8]^=1;var payload=stale.AsSpan(4).ToArray();AL5ReadOnlyCoreSession.SetCrc(payload);payload.CopyTo(stale,4);
                Check(path.ObserveSavedReply(stale)==AL5ReadOnlyCoreReply.Unrelated && path.PreparedBytesObserved==0,"stale epoch never consumes prepared slot");first=false;
            }
            Check(path.ObserveSavedReply(reply)==AL5ReadOnlyCoreReply.Matched,"prepared bank correlated read");
        }
    }
    static async Task SecurityAndBackupCases()
    {
        foreach((string wire,AL5SavedSecurityFailure failure) in new[]{
            ("6cf018670235",AL5SavedSecurityFailure.InvalidKey),("6cf018670236",AL5SavedSecurityFailure.AttemptsExceeded),
            ("6cf018670237",AL5SavedSecurityFailure.DelayRequired),("6cf018670299",AL5SavedSecurityFailure.Malformed),
            ("6cf0187f2722",AL5SavedSecurityFailure.NegativeResponse),("6cf01867023400",AL5SavedSecurityFailure.Malformed)})
        {
            var s=SeededSecurity();s.ReviewSavedKeyRequest(Hex("6c18f02702bc08"));s.ObserveSavedKeyRequestAccepted(Hex("6c18f02702bc08"));s.ObserveSavedKeyReply(Hex(wire));
            Check(s.State==AL5SavedSecurityState.Stopped && s.Failure==failure,"key reply failure retained");Reject(()=>s.ReviewSavedKeyRequest(Hex("6c18f02702bc08")));
            results.Add(new {name="security_key_reply",wire,failure=failure.ToString(),passed=true});
        }
        foreach((string wire,AL5SavedSecurityFailure failure) in new[]{
            ("6cf018670137",AL5SavedSecurityFailure.ShortSeedReply),("6cf01867010000",AL5SavedSecurityFailure.UnsupportedSeed),
            ("6cf018670137ff",AL5SavedSecurityFailure.UnsupportedSeed),("6cf01867011234",AL5SavedSecurityFailure.UnsupportedSeed),
            ("6cf01867019ce500",AL5SavedSecurityFailure.Malformed)})
        {
            var s=new AL5SavedSecurityExchange(original);s.ObserveSavedSeedRequestAccepted(Hex("6c18f02701"));s.ObserveSavedSeedReply(Hex(wire));
            Check(s.Failure==failure && !s.SavedAcceptanceObserved,"seed never confers acceptance");
            results.Add(new {name="security_seed_reply",wire,failure=failure.ToString(),passed=true});
        }
        {
            var s=SeededSecurity();s.ReviewSavedKeyRequest(Hex("6c18f02702bc08"));Reject(()=>s.ReviewSavedKeyRequest(Hex("6c18f02702bc08")));
            Check(s.Failure==AL5SavedSecurityFailure.InvalidSequence,"one review per seed");
            var noSeed=new AL5SavedSecurityExchange(original);Reject(()=>noSeed.ReviewSavedKeyRequest(Hex("6c18f02702bc08")));
            var badBoot=(byte[])original.Clone();badBoot[0x3FDA]^=1;Reject(()=>new AL5SavedSecurityExchange(badBoot));
            var selectorOne=(byte[])original.Clone();selectorOne[0x10954]=1;Reject(()=>new AL5SavedSecurityExchange(selectorOne));
            results.Add(new {name="security_ownership_and_boot_profile",passed=true});
        }
        foreach((string reply,AL5OfflineDispatchStop stop) in new[]{("6cf018670235",AL5OfflineDispatchStop.SecurityInvalidKey),
            ("6cf018670236",AL5OfflineDispatchStop.SecurityAttemptsExceeded),("6cf018670237",AL5OfflineDispatchStop.SecurityDelayRequired),
            ("6cf0187f2722",AL5OfflineDispatchStop.SecurityNegativeResponse)})
        {
            string[] modified=lines.Select(l=>l=="R 6cf018670234"?"R "+reply:l).ToArray();
            Check(!modified.SequenceEqual(lines),"negative security fixture is actually altered");
            var peer=new Peer(modified,original);var io=new MemoryIo(peer);var session=Session(io);
            var report=await session.RunUntilReviewAsync(CancellationToken.None);
            report=await session.SubmitSavedSecurityEvidenceAsync(Hex("6c18f02702bc08"),CancellationToken.None);
            Check(report.Outcome==AL5WriteExecutionOutcome.Stopped && report.StopReason==stop && report.AcknowledgedBlocks==0,"security rejection prevents entry and erase");
            int sends=io.Sends;await session.RunUntilReviewAsync(CancellationToken.None);Check(sends==io.Sends,"no retry after lockout/rejection");
            results.Add(new {name="executor_security_rejection",reply,stop=stop.ToString(),passed=true});
        }
        {
            Reject(()=>new AL5SavedBackupPath("same nonce",new byte[]{1,2,3,4,5,6,7,8},new byte[]{1,2,3,4,5,6,7,8}));
            var path=AcquireOriginal(original,"synthetic-original-and-prepared");var peer=new Peer(lines,original);peer.Flash[0x6000]^=1;
            AcquirePrepared(path,peer.Flash);var originalCopy=path.CopyOriginalImage();originalCopy[0]^=1;
            var banks=path.CopyPreparedReference();Check(banks.ChangedBytes==1 && !path.PreEntryPhysicalAcquisitionVerified,"saved epochs retain delta without physical claim");
            var io=new MemoryIo(peer);var session=Session(io);var report=await session.RunUntilReviewAsync(CancellationToken.None);
            report=await session.SubmitSavedSecurityEvidenceAsync(Hex("6c18f02702bc08"),CancellationToken.None);
            Check(report.Outcome==AL5WriteExecutionOutcome.PreparationBackupReviewRequired,"saved backup cannot skip erase boundary");
            report=await session.RecordSavedBackupPathAsync(path,CancellationToken.None);
            while(report.Outcome==AL5WriteExecutionOutcome.ChecksumReviewRequired)report=await session.ReviewChecksumRetryAsync(CancellationToken.None);
            Check(report.BackupEvidenceId==path.EvidenceId && report.OriginalReferenceSha256==path.OriginalSha256 && report.SavedSecurityState==AL5SavedSecurityState.Accepted,"executor retains evidence identity and saved security acceptance");
            Check(session.VerifySavedReadback(peer.Flash).Outcome==AL5WriteExecutionOutcome.SavedComparisonMatched,"correlated epochs feed unchanged write and full saved comparison");
            results.Add(new {name="correlated_backup_to_unchanged_executor",passed=true,path.OriginalBytesObserved,path.PreparedBytesObserved,readback_is_synthetic=true});
        }
        {
            var changed=(byte[])original.Clone();changed[0xFFFFF]^=1;var path=AcquireOriginal(changed,"different-original");AcquirePrepared(path,changed);
            var peer=new Peer(lines,original);var io=new MemoryIo(peer);var session=Session(io);await session.RunUntilReviewAsync(CancellationToken.None);
            await session.SubmitSavedSecurityEvidenceAsync(Hex("6c18f02702bc08"),CancellationToken.None);int sends=io.Sends;
            await RejectAsync(()=>session.RecordSavedBackupPathAsync(path,CancellationToken.None));Check(io.Sends==sends,"different original hash cannot authorize erase");
            var partial=new AL5SavedBackupPath("partial",Hex("1111111111111111"),Hex("2222222222222222"));byte[] request=partial.BeginNextSavedRequest();partial.ObserveSavedReply(ReadReply(request,original));partial.TimeoutOrCancel();
            Reject(()=>partial.CopyOriginalImage());Reject(()=>partial.CopyPreparedReference());
            results.Add(new {name="incomplete_and_foreign_backup_rejected",passed=true});
        }
        {
            var owned=(byte[])original.Clone();var path=AL5SavedBackupPath.FromSavedExternalOriginal("external-saved-original",owned,Hex("1234567890abcdef"));
            owned[0]^=1;Check(path.CopyOriginalImage().SequenceEqual(original) && path.OriginalBytesObserved==0x100000 && path.OriginalSourceKind=="ExternalSavedImage","external original is immutable complete saved data, not a fabricated response campaign");
            Reject(()=>path.BeginNextSavedRequest());Reject(()=>path.ObserveSavedReply(Array.Empty<byte>()));
            var peer=new Peer(lines,original);peer.Flash[0x6000]^=1;AcquirePrepared(path,peer.Flash);
            var io=new MemoryIo(peer);var session=Session(io);await session.RunUntilReviewAsync(CancellationToken.None);
            var report=await session.SubmitSavedSecurityEvidenceAsync(Hex("6c18f02702bc08"),CancellationToken.None);
            Check(report.Outcome==AL5WriteExecutionOutcome.PreparationBackupReviewRequired,"external file cannot skip pre-erase prepared review");
            report=await session.RecordSavedBackupPathAsync(path,CancellationToken.None);
            while(report.Outcome==AL5WriteExecutionOutcome.ChecksumReviewRequired)report=await session.ReviewChecksumRetryAsync(CancellationToken.None);
            Check(report.BackupEvidenceId==path.EvidenceId && report.OriginalReferenceSha256==path.OriginalSha256,"external original retains the executor hash/evidence binding");
            Check(session.VerifySavedReadback(peer.Flash).Outcome==AL5WriteExecutionOutcome.SavedComparisonMatched && !path.PreEntryPhysicalAcquisitionVerified && !report.PhysicalBackupVerified && !report.ReadyToFlash,"external saved original feeds unchanged rehearsal without physical claims");
            results.Add(new {name="external_original_to_unchanged_executor",passed=true,readback_is_synthetic=true});
        }
        {
            var changed=(byte[])original.Clone();changed[0xFFFFF]^=1;
            var path=AL5SavedBackupPath.FromSavedExternalOriginal("foreign-external-original",changed,Hex("1234567890abcdef"));AcquirePrepared(path,changed);
            var peer=new Peer(lines,original);var io=new MemoryIo(peer);var session=Session(io);await session.RunUntilReviewAsync(CancellationToken.None);
            await session.SubmitSavedSecurityEvidenceAsync(Hex("6c18f02702bc08"),CancellationToken.None);int sends=io.Sends;
            await RejectAsync(()=>session.RecordSavedBackupPathAsync(path,CancellationToken.None));Check(io.Sends==sends,"foreign external original cannot authorize another send");
            results.Add(new {name="foreign_external_original_rejected",passed=true});
        }
        {
            Reject(()=>AL5SavedBackupPath.FromSavedExternalOriginal("short",new byte[0x80000],Hex("1234567890abcdef")));
            Reject(()=>AL5SavedBackupPath.FromSavedExternalOriginal("bad nonce",original,new byte[7]));
            var path=AL5SavedBackupPath.FromSavedExternalOriginal("interrupted-external",original,Hex("1234567890abcdef"));
            path.TimeoutOrCancel();Reject(()=>path.RecordEntryBoundaryForOfflineReview());Reject(()=>path.BeginNextSavedRequest());Reject(()=>path.CopyPreparedReference());
            Check(path.Phase==AL5SavedBackupPhase.Stopped && !path.ReadyToFlash,"external saved data does not reopen a stopped acquisition");
            results.Add(new {name="external_original_bounds_and_stop",passed=true});
        }
    }
}

using PcmHacking;

static partial class Program
{
    static void ReadbackEpochCases(byte[] baseline,string journalReport)
    {
        byte[] prepared=baseline.AsSpan(0x4000,0x4000).ToArray();
        AL5CalibrationWriteCandidate Candidate()=>RehearseSavedPreparedCandidate(baseline,prepared);
        AL5SavedReadbackEpoch New(AL5CalibrationWriteCandidate c,string id,AL5SavedReadbackEpochKind kind=AL5SavedReadbackEpochKind.AfterCleanupStartupUnobserved)=>
            AL5SavedReadbackEpoch.CreateForCompletedSavedCandidate(c,id,kind,Hex("0102030405060708"),Hex("1112131415161718"),Hex("2122232425262728"));
        void Closed(AL5SavedReadbackEpoch e)
        {
            var a=e.AssessSavedEvidence();Check(!a.SnapshotCoherenceVerified && !a.ReaderEntryEffectsVerified && !a.PhysicalReadbackVerified &&
                !a.PhysicalResetVerified && !a.PreservationVerified && !a.ReadyToFlash && !a.LiveUploadEnabled &&
                !a.LiveExecutionEnabled && !a.LiveWriteEnabled && !a.StartupHistoryPhysicallyVerified &&
                !a.CrossSessionNonceUniquenessProven,"Correlation, equality and declared startup are not physical epoch authority");
        }
        void Record(string name,AL5SavedReadbackEpoch e)=>results.Add(new {name,passed=true,
            phase=e.Phase.ToString(),stop_reason=e.StopReason.ToString(),assessment=e.AssessSavedEvidence()});
        void Feed(AL5SavedReadbackEpoch e,byte[] pre,byte[] middle,byte[] post)
        {
            while(e.Phase!=AL5SavedReadbackEpochPhase.Complete)
            {
                var phase=e.Phase;byte[] request=e.BeginNextSavedRequest();
                Check(e.ObserveSavedReply(ReadReply(request,phase==AL5SavedReadbackEpochPhase.BanksBeforeImage?pre:
                    phase==AL5SavedReadbackEpochPhase.FullImage?middle:post))==AL5ReadOnlyCoreReply.Matched,"Owned full-address response advances only its campaign");
            }
        }
        {
            var c=Candidate();byte[] image=c.CopyExpectedSavedImage();var e=New(c,"unchanged_control");
            Reject(()=>e.VerifySavedComparison(c));Reject(()=>e.CopyObservedImageForDiagnosis());
            Feed(e,image,image,image);var a=e.AssessSavedEvidence();
            Check(a.CompleteCorrelatedCoverage && a.BanksAgreeAcrossSavedObservations==true && a.MatchedReplies==33792 &&
                a.FullImageBytes==0x100000 && a.BeforeBankBytes==0x4000 && a.AfterBankBytes==0x4000,"Distinct full image and both complete bank samples are retained");
            var foreign=Candidate();Reject(()=>e.VerifySavedComparison(foreign));
            Check(foreign.State==AL5CapturedWriteState.AwaitingSavedVerification && !a.SavedComparisonAttempted,"An equal-hash foreign candidate cannot consume an epoch");
            var copy=e.CopyObservedImageForDiagnosis();copy[0]^=1;
            Check(e.CopyObservedImageForDiagnosis()[0]==image[0],"Readback export is an owned copy");
            e.VerifySavedComparison(c);Check(e.AssessSavedEvidence().StrictSavedComparisonMatched,"Unchanged full equality still uses the existing strict comparator");
            Reject(()=>e.BeginNextSavedRequest());Reject(()=>e.ObserveSavedReply(Hex("6df018f1")));
            Closed(e);Record("unchanged_correlated_epoch_and_foreign_owner",e);
        }
        foreach(string change in new[]{"after","middle_aba"})
        {
            var c=Candidate();byte[] image=c.CopyExpectedSavedImage(),middle=(byte[])image.Clone(),post=(byte[])image.Clone();
            if(change=="after")post[0x4A1D]^=1;else middle[0x4A1D]^=1;
            var e=New(c,change);Feed(e,image,middle,post);var a=e.AssessSavedEvidence();
            Check(a.CompleteCorrelatedCoverage && a.BanksAgreeAcrossSavedObservations==false &&
                (change!="middle_aba" || a.BeforeToAfterBankDifferences==0 && a.BeforeToImageBankDifferences==1),
                "Matching outer bank samples cannot hide a different bank view in the full image");
            Reject(()=>e.VerifySavedComparison(c));Check(c.State==AL5CapturedWriteState.AwaitingSavedVerification && !a.SavedComparisonAttempted,
                "Unstable acquisition remains diagnostic and does not stop or silently verify the writer");
            Check(e.CopyObservedImageForDiagnosis().SequenceEqual(middle),"Full diagnostic bytes survive an unstable review");
            Closed(e);Record("bank_observation_disagreement_"+change,e);
        }
        {
            var c=Candidate();byte[] image=c.CopyExpectedSavedImage(),transient=(byte[])image.Clone();var e=New(c,"unobserved_aba");bool hiddenChange=false;
            while(e.Phase!=AL5SavedReadbackEpochPhase.Complete)
            {
                byte[] request=e.BeginNextSavedRequest();int address=(request[20]<<16)|(request[21]<<8)|request[22];
                if(e.Phase==AL5SavedReadbackEpochPhase.FullImage && address==0x8000){transient[0x4A1D]^=1;hiddenChange=true;}
                if(e.Phase==AL5SavedReadbackEpochPhase.BanksAfterImage)transient[0x4A1D]=image[0x4A1D];
                Check(e.ObserveSavedReply(ReadReply(request,transient))==AL5ReadOnlyCoreReply.Matched,"Synthetic hidden transition never changes an observed response");
            }
            Check(hiddenChange && e.AssessSavedEvidence().BanksAgreeAcrossSavedObservations==true &&
                e.CopyObservedImageForDiagnosis().SequenceEqual(image),"All observations can agree despite a synthetic intervening bank change/restoration");
            e.VerifySavedComparison(c);Closed(e);Record("unobserved_aba_keeps_coherence_unproven",e);
        }
        foreach(int address in new[]{0,0x15FD7,0x15FD8,0x1FFFE,0x20000,0xC4C66})
        {
            var c=Candidate();byte[] image=c.CopyExpectedSavedImage();image[address]^=1;var e=New(c,"protected_corruption_"+address.ToString("x"));
            Feed(e,image,image,image);Check(e.AssessSavedEvidence().BanksAgreeAcrossSavedObservations==true,"Bank agreement says nothing about other regions");
            e.VerifySavedComparison(c);Check(c.State==AL5CapturedWriteState.Stopped && !e.AssessSavedEvidence().StrictSavedComparisonMatched,
                "Boot, compensation, collateral, marker and OS differences remain strict failures");
            Closed(e);Record("strict_region_corruption_"+address.ToString("x"),e);
        }
        foreach(var epoch in LoadSavedJournalEpochs(journalReport,baseline))
        {
            var c=RehearseSavedPreparedCandidate(baseline,epoch.Before);byte[] image=c.CopyExpectedSavedImage();
            epoch.Review.CopyPredictedBanks().CopyTo(image,0x4000);var e=New(c,"journal_"+epoch.Label,AL5SavedReadbackEpochKind.AfterDeclaredStartup);
            Feed(e,image,image,image);var d=e.DiagnoseSavedStartupBanks(epoch.Review);
            Check(d.MatchesSavedPrediction && d.ChangedFromPreparedBytes==epoch.Changed && e.AssessSavedEvidence().BanksAgreeAcrossSavedObservations==true,
                "Reuse the exact ordered native startup prediction, without adopting observed banks as expected");
            e.VerifySavedComparison(c);Check(c.State==AL5CapturedWriteState.Stopped && !e.AssessSavedEvidence().StrictSavedComparisonMatched &&
                e.DiagnoseSavedStartupBanks(epoch.Review).MatchesSavedPrediction,"Explained startup changes remain a failed strict preservation comparison");
            Closed(e);Record("native_startup_prediction_is_not_preservation_"+epoch.Label,e);
        }
        foreach(bool completedImage in new[]{false,true})
        {
            var c=Candidate();byte[] image=c.CopyExpectedSavedImage();var e=New(c,"partial_"+completedImage);
            while(e.Phase==AL5SavedReadbackEpochPhase.BanksBeforeImage || completedImage && e.Phase==AL5SavedReadbackEpochPhase.FullImage)
            {byte[] request=e.BeginNextSavedRequest();e.ObserveSavedReply(ReadReply(request,image));}
            byte[] pending=e.BeginNextSavedRequest();e.TimeoutOrCancel();var a=e.AssessSavedEvidence();
            Check(a.Phase==AL5SavedReadbackEpochPhase.Stopped && a.BanksAgreeAcrossSavedObservations==null && !a.CompleteCorrelatedCoverage,
                "Partial bank/image stages never acquire completion or equality by padding");
            Reject(()=>e.VerifySavedComparison(c));Reject(()=>e.ObserveSavedReply(ReadReply(pending,image)));
            if(completedImage)Check(e.CopyObservedImageForDiagnosis().SequenceEqual(image),"A later stop retains completed image bytes as diagnostic-only");
            else Reject(()=>e.CopyObservedImageForDiagnosis());
            Closed(e);Record("partial_epoch_retains_unknowns_"+completedImage,e);
        }
        {
            var c=Candidate();byte[] image=c.CopyExpectedSavedImage();var e=New(c,"stale_and_wrong_bank");byte[] first=e.BeginNextSavedRequest();
            byte[] stale=ReadReply(first,image);Check(e.ObserveSavedReply(stale)==AL5ReadOnlyCoreReply.Matched,"First correlated bank response");
            byte[] next=e.BeginNextSavedRequest();Check(e.ObserveSavedReply(stale)==AL5ReadOnlyCoreReply.Unrelated && e.BeforeBankBytes==32,"Duplicate sequence cannot consume another request");
            byte[] alias=ReadReply(next,image),payload=alias.AsSpan(4).ToArray();payload[16]^=1;AL5ReadOnlyCoreSession.SetCrc(payload);payload.CopyTo(alias,4);
            Check(e.ObserveSavedReply(alias)==AL5ReadOnlyCoreReply.Unrelated,"Full bank address is checked, not a low-16 echo");
            e.RecordInterveningResetOrStartupForOfflineReview();Reject(()=>e.ObserveSavedReply(ReadReply(next,image)));
            Check(e.StopReason==AL5SavedReadbackEpochStop.DeclaredInterveningResetOrStartup,"Declared acquisition boundary invalidates rather than requalifies the epoch");
            Closed(e);Record("correlation_and_intervening_startup_guards",e);
        }
        {
            var c=Candidate();var e=New(c,"malformed");e.BeginNextSavedRequest();
            Check(e.ObserveSavedReply(Hex("6df018f16172"))==AL5ReadOnlyCoreReply.Malformed && e.StopReason==AL5SavedReadbackEpochStop.MalformedReply,
                "Malformed correlated envelope stops the acquisition");Closed(e);Record("malformed_readback_epoch_reply",e);
        }
        {
            var c=Candidate();byte[] image=c.CopyExpectedSavedImage();var e=New(c,"cross_stage_nonce");byte[] first=e.BeginNextSavedRequest(),old=ReadReply(first,image);
            e.ObserveSavedReply(old);
            while(e.Phase!=AL5SavedReadbackEpochPhase.BanksAfterImage)
            {byte[] request=e.BeginNextSavedRequest();e.ObserveSavedReply(ReadReply(request,image));}
            byte[] pending=e.BeginNextSavedRequest();
            Check(e.ObserveSavedReply(old)==AL5ReadOnlyCoreReply.Unrelated && e.AfterBankBytes==0,
                "Same sequence/address/count from the before sample cannot satisfy the after sample's distinct nonce");
            e.TimeoutOrCancel();Reject(()=>e.ObserveSavedReply(ReadReply(pending,image)));
            Closed(e);Record("before_reply_cannot_satisfy_after_sample",e);
        }
        {
            var c=Candidate();byte[] image=c.CopyExpectedSavedImage();var e=New(c,"parent_stopped");Feed(e,image,image,image);
            c.TimeoutOrCancel();Reject(()=>e.VerifySavedComparison(c));
            Check(!e.AssessSavedEvidence().SavedComparisonAttempted && !e.AssessSavedEvidence().StrictSavedComparisonMatched,
                "Completed observation cannot reopen a stopped parent candidate");Closed(e);Record("stopped_candidate_is_not_reopened_by_epoch",e);
        }
        {
            var c=Candidate();byte[] n=Hex("0102030405060708"),m=Hex("1112131415161718"),p=Hex("2122232425262728");
            Reject(()=>AL5SavedReadbackEpoch.CreateForCompletedSavedCandidate(c,"same_nonce",AL5SavedReadbackEpochKind.AfterDeclaredStartup,n,n,p));
            Reject(()=>AL5SavedReadbackEpoch.CreateForCompletedSavedCandidate(c,"bad_kind",(AL5SavedReadbackEpochKind)99,n,m,p));
            Reject(()=>AL5SavedReadbackEpoch.CreateForCompletedSavedCandidate(c,"zero_nonce",AL5SavedReadbackEpochKind.AfterDeclaredStartup,new byte[8],m,p));
            var unstarted=new AL5CalibrationWriteCandidate(loader,baseline.AsSpan(0x8000,AL5CalibrationInspection.Length).ToArray(),baseline);Reject(()=>New(unstarted,"early"));
            var e=AL5SavedReadbackEpoch.CreateForCompletedSavedCandidate(c,"nonce_ownership",AL5SavedReadbackEpochKind.AfterDeclaredStartup,n,m,p);n[0]^=1;
            Check(e.BeforeNonceHex=="0102030405060708" && e.BeginNextSavedRequest()[8]==1,"Campaign owns correlation bytes and their recorded identity");
            e.TimeoutOrCancel();Closed(e);Record("epoch_profile_nonce_and_order_ownership",e);
        }
    }
}

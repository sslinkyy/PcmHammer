# Startup bank prediction and strict verification

This continuation remains offline. No upload, execution, vehicle access, programmer operation or live write is enabled. Separate emulator contexts do not deliver the captured finalizer's physical reset.

## Native continuation

`trace_journal_restart.py` runs the existing bounded preparation model and three native application-startup contexts with explicit bank overlays. The full saved reference is validated before overlaying only `0x4000..0x7FFF`; boot, calibration and OS bytes are unchanged. The output distinguishes the selected reference hash, overlaid image hash and bank hash. The storage implementation remains intercepted; successful programs are atomic host effects and enforce one-to-zero transitions. Each startup uses the existing explicit peripheral assumptions and 320 scripted timer-body calls, with no physical timing claim.

The retained historical baseline reaches 13 modeled small-record programs and eight changed bytes at `0x4A1D`, `0x4A1E`, `0x4A23`, `0x4A29`, `0x4A2F`, `0x4A41`, `0x4A42`, `0x4A47`. The bounded preparation model selects a committed parent in bank `0x6000`. Restart from those modeled prepared banks reaches the same program count and byte count in the corresponding `0x6Axx` slots. A second restart from that output reaches ten programs and six changed bytes: `0x6A1E`, `0x6A23`, `0x6A2A`, `0x6A2F`, `0x6A42`, `0x6A47`.

The native reader/writer calls are now recorded with slot, caller return, parent cache, buffer, stack ownership and return D0. On the second restart, slots 0, 1 and 3 read successfully instead of appearing erased. Existing bit-vector logic changes payload bytes again, including `7F` to `3F`. The small-record writer's sampled return D0 is retained as a numeric observation, not interpreted as a success result. Prior [preamble](../AL5/CONTEXT_PREAMBLE.md) and [failure](../AL5/SMALL_RECORD_FAILURES.md) evidence still applies.

These cases disprove using a universal eight-byte count, fixed absolute address mask, or the prior observed post-startup bank image as a general preservation rule. They do not qualify all reset statuses, elapsed times, peripheral inputs, bank states or eventual journal rollover.

## Diagnostic implementation

`AL5SavedBankTransitionReview` replays caller-supplied saved-model operations in order from an immutable prepared-bank copy. The supported layout is the four twelve-byte slots at bank offsets `0xA1C`, `0xA28`, `0xA34`, `0xA40`. Operations require the traced return sites `0x229C2` (pending marker), `0x229DC` (ten-byte payload), or `0x229F6` (committed marker), exact before bytes and one-to-zero transitions. An operation outside that layout, reordered state, altered before data or implied erase is rejected. This is deliberately bounded profile recognition, not a general journal decoder or physical event recorder.

The assessment compares **every bank byte**, rather than ignoring any region or treating changed addresses as unrestricted. It reports changes from prepared data and differences from the exact saved prediction. A corruption at a legitimately changing address still differs from the prediction. Empty operation lists describe a no-change prediction; they cannot confer preservation authority.

`AL5CalibrationWriteCandidate.DiagnoseSavedStartupBanks` additionally requires complete cleanup, the same original-image hash, explicitly recorded prepared-bank hash, and complete full-image input. It is a bank-only diagnostic. It never changes the candidate's strict comparison result, terminal state or live gates. It can explain a stopped comparison without clearing that stop. Boot/OS/calibration/collateral verification still belongs to the full comparator. In particular, a bank prediction match says nothing about a separately corrupted boot byte.

The existing full comparator continues to reject all modeled eight- or six-byte bank transitions. None of these results is promoted to physically verified preservation. A post-restart image is not its own expected baseline.

## File-only commands

With the pinned saved full reference and existing Capstone/Unicorn dependencies:

```text
python Tools/AL5/trace_journal_restart.py --full-reference FULL.bin --output NEW-native-directory

dotnet LocalOnly/SavedBackupTool/bin/SavedBackupTool.dll --startup-bank-review ORIGINAL-full.bin PREPARED-banks.bin READBACK-full.bin NEW-native-directory/report.json prepared_restart evidence-id NEW-review-directory
```

The diagnostic validates the selected native-report schema, exact original and overlaid image hashes, prepared-bank hash, bounded endpoint, operation bytes and final prediction digest. It retains input paths and hashes. Physical/live flags must remain false. The report itself remains caller-supplied saved evidence, not a trusted observation of the vehicle. The tool exports predicted banks and a diagnostic JSON; it does not acquire or rewrite controller data. Existing outputs are rejected.

## Validation and next gate

Native report/source hashes and ordered replay are checked separately from the C# implementation. The compiled exporter covers all three epochs, corruption both inside and outside predicted addresses, altered provenance, wrong original/prepared epochs, caller/layout/order/digest errors, promoted physical flags, partial inputs, duplicate/missing cases and existing outputs. Production-candidate tests feed all three native predictions into complete scripted calibration-write rehearsals, verify the diagnostic without accepting preservation, and retain rejection of other protected-region corruption and foreign epochs.

The remaining physical question is which exact bank transition occurs on the spare between the recorded prepared epoch and independent readback, with a known reset/startup history. The current models are useful predictions to test against that acquisition. They do not establish a safe pre-finalization reader, a physical reset deadline, atomic snapshot coherence or AL5 restoration.

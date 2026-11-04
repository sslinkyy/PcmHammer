# External original acquisition and finalizer timing

This continuation reviews the retained programmer work before extending the AL5 tools. The spare is still in transit. No programmer, adapter, vehicle, upload, execution or live write is accessed or enabled.

## Existing equipment evidence

The October 15 retained result documents Xgpro 13.16, T48 firmware 00.01.39 and ADP_S44_EX-1, with successful loose Intel TB28F400B5B @SOP44 programming/verification and a separate matching readback. The raw 512 KiB readback's digest and its equality to the explicitly converted programmer image were rechecked from saved files. The original OEM bytes were not overwritten. The retained vendor-linked T48 list includes `AM29F800BB @SOP44`.

The earlier request to identify equipment already documented in this work was unnecessary. Exact AL5 chip identification, programmer representation and actual AL5 read/restoration remain separate qualification steps; the Intel chip's size, profile and pair conversion must not be reused by assumption. See [physical hardware evidence](../AL5/PHYSICAL_HARDWARE_20261010.md).

## Original path now implemented

The file-only saved backup tool has two additive modes:

```text
dotnet LocalOnly/SavedBackupTool/bin/SavedBackupTool.dll --external-chip first-raw.bin second-raw.bin cpu-bytes evidence-id NEW-original-directory
dotnet LocalOnly/SavedBackupTool/bin/SavedBackupTool.dll --external-chip first-raw.bin second-raw.bin swap16 evidence-id NEW-original-directory
```

Select exactly one representation. Both input files must be exactly 1,048,576 bytes, equal, nonblank and nonzero. The selected representation must pass the existing supported AL5 boot/OS/calibration profile checks. The tool never guesses byte order, pads a short image, strips a header or substitutes Intel data. It preserves both raw files and exports a separate canonical saved original, its banks and provenance report. Same selected paths/symlink targets and existing output directories are rejected. Distinct path names, matching bytes and profile checks still cannot prove separate physical reads or hard-link identity; physical flags remain false.

`AL5SavedBackupPath.FromSavedExternalOriginal` owns a clone of that canonical full image and its hash. It explicitly records `ExternalSavedImage` as the source kind, without fabricating a nonce or 32,768 original-reader replies. Before prepared acquisition, the caller must record the separate entry boundary. Prepared replies still require the production nonce/sequence/full-address/count/CRC correlation and all 16,384 bank bytes.

```text
dotnet LocalOnly/SavedBackupTool/bin/SavedBackupTool.dll --external-prepared ORIGINAL-directory prepared-transcript.txt prepared-nonce-hex evidence-id --entry-boundary-recorded NEW-joined-directory
```

The join validates all original artifacts against the importer report, including raw-to-canonical representation. It rejects altered raw/canonical/bank files and promoted physical flags. It exports the immutable original, original banks, separate prepared banks and their hashes/delta. The entry flag records offline ordering; it sends no request and proves no physical transition.

The existing executor consumes this new owner through its original-hash binding and pre-erase prepared-bank review. Scripted Vehicle/GT tests exercise an entire unchanged-calibration write and saved comparison from this source. A foreign external original cannot authorize another send; incomplete or stopped prepared acquisition cannot satisfy the gate. The public writer remains unconditionally disabled.

An external dump may represent the chip before the spare's first bench startup. Its difference from prepared banks can therefore include ordinary startup **and** programming preparation. The report labels this combined scope; it does not attribute every changed byte to programming entry. Raw external originals and post-startup resident observations are different epochs.

## Finalizer-to-park trace

The original native finalizer model stopped at shared exit `0xFF9236`. The new optional continuation executes its two native delay loops while suppressing interface stores and stubbing watchdog/sender helpers. At `0xFF924A`, the absolute-short operand sign-extends to `0xFFFF8000`. Under the existing declared 24-bit mapping that is retained RAM `0xFF8000`, not calibration flash `0x8000` and not an identified hardware reset register.

Two bounded modes stop before that store or model the `D0C2` RAM word and reach park `0xFF9250`. No physical reset is delivered. Conditional follow-on boot runs use separate CPU contexts, the same pinned historical flash and explicit retention/reset-status hypotheses. With retained `D0C2` and numeric statuses `00`, `20`, `40`, `80`, native boot verifies the saved OS, sets marker `2FE6` and reaches application transfer. This is code-path evidence, not proof of reset timing, marker survival or actual device status semantics.

Both modeled final success `86` and bad-sum status `FF` reach the marker/park tail. Marker-program readback failure instead returns toward receive with status `F8` and an outstanding four-byte stack frame. Deliberately failing finalization is not a supported pause or recovery strategy.

No receive loop or host readback service is entered between final status construction and the park point on the examined success path. The busy delays provide no qualified host verification window. The earlier term "reset register" for the retained word was incorrect; sender metadata and its tests now use the marker classification.

## Pre-finalization boundary and remaining verification work

`AL5OfflineWriteBoundary.BeforeFinalization` now terminates the offline dispatcher after 192 acknowledged data blocks, before reserving or submitting `36 FF`. Existing enum numeric values are preserved. Actual Vehicle/GT binding tests cover both adapter-ack orderings; dispatcher and GT serialization tests verify that the finalization request is absent and terminal callbacks cannot resume it.

This boundary has already passed erase/programming in the model. It is **not** a safe entry-only test, a physical stable-pause guarantee, an enabled reader or permission to upload/execute a new kernel. Loader idle-timeout and readback capability still need qualification. Full saved verification remains prohibited there by the existing cleanup/verification state contract.

The write qualification must distinguish:

1. External original: saved chip state before the chosen bench actions.
2. Prepared banks: separate state before erase.
3. Data acknowledged, pre-finalization: inspectable offline boundary; no physical readback service established.
4. Final status/marker/park: software observations; actual reset remains unproven.
5. Application restart and periodic operation: journal writes can change banks before a later read.

The current post-cleanup comparator correctly rejects unexplained bank changes. A post-restart bank file must not become its own expected baseline. Before live qualification, select and prove either a valid independent pre-finalization readback mechanism or a separately justified post-restart preservation comparison that explains actual journal transitions without ignoring the bank region. External original acquisition removes the missing-byte bootstrap problem at the data-workflow level; it does not by itself establish either comparison window, safe reader entry or AL5 recovery.

## Validation

- External importer: actual compiled-tool checks cover CPU-byte and explicitly swapped fixtures, wrong representation, mismatches, blank/zero data, oversized files, the retained 512 KiB Intel readback, damaged AL5 profiles, self-comparison and existing output.
- External original/prepared join: complete and stale-epoch controls plus partial/wrong-nonce/tampered-artifact/promoted-flag/missing-boundary rejection; original and prepared files remain separate.
- Production executor: unchanged saved lifecycle from the external owner, foreign-hash and stopped/bounds rejection, plus both pre-finalization ACK orderings.
- Native timing: finalizer through marker/park, bad sum, marker readback failure, default eight-case behavior, conditional boot routing and sender/planner safety checks. Every physical/live readiness flag stays false.

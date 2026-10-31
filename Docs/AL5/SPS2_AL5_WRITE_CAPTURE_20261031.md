# SPS2 AL5 write capture, 2026-10-31

## Result and boundaries

SPS2 displayed Action Complete; its programming event ended with result 0 at 00:24:11 local time. This is an observed SPS success, not an independent flash readback or interrupted-write recovery test. PcmHammer live writes remain disabled. No DTC clearing or ignition reset was performed by this analysis. The completion screen's generic 30-second ignition instruction was conditional; its controller-specific instruction was M5741 concerning DTC clearing.

The GT-only USB capture was stopped using its exact session stop request. The supervisor observed graceful exit 0, 1,461,051 saved bytes, no helper error and released ownership. SHA256: dc82b7c5df8d8ae1f3150447c4acfdc31ae9459d45dbeac7c7cb25d11129ce8e. PCAP structure and URB pairing have no findings. Two selected IN completions have status 0xC0010000 and empty payloads; these remain explicit observations. Clean shutdown and checksum-valid DVI reconstruction do not prove physical VPW losslessness.

Private evidence is retained under LocalOnly/usb_capture_setup_20261030/sps_al5_preprogram_01. It contains the PCAP, capture receipt, final SPS log, downloaded originals, expanded copies, loader candidate and importer reports/corpora. No proprietary binary is added to the public repository.

## Utility and actual downloaded code

SPS downloaded extensionless gzip files to the newly created sps/spsCache/spsCacheInternal directory and copied them to sps/spsDebug. The initially watched bufferedFiles directory remained empty. The files were manually preserved during programming, before completion.

- Utility 15107661 expands to 4,288 bytes, SHA256 483c45ab70d1328052570c0d04d219da652cca9e68e3a8fca53cbac6bbccfb0c.
- Bytes 0x1AE through 0x10BF inclusive are 3,858 loader bytes, SHA256 4a03452ef44e85d1874f6b519f8b3e7fd3c2bca7332ecf11fb1aaaa1b6372d80.
- Those bytes exactly match the captured extended DVI TX payload's Mode 36/submode 80 code, addressed to 0xFF9006. Reply: 6C F0 18 76 80 73.
- The preceding utility bytes contain a control table whose logged steps include security, preparation, B0 loader entry and B4 module staging. Detailed table semantics and loader disassembly remain unresolved.

## Module staging and acknowledgements

The capture has 180 Mode 36/submode 00 blocks, each 4,096 data bytes, addressed to the same RAM staging address 0xFF8000. This is not a flash destination map. All 737,280 staged bytes are accounted for by:

- OS 15184109: 679,828 exact downloaded bytes in 166 blocks, followed by 108 zero-padding bytes.
- Calibration 15183960: 57,304 exact downloaded bytes in 14 blocks, followed by 40 zero-padding bytes.

Expanded OS SHA256: 145d0dde8c4de88e3145b5693685ab28958d1dda70743c589cc0c7deaa4b45e7. Expanded calibration SHA256: 140b70ea90cb57c20aaab2d9641d2b7caaa6bf312c89bd9369b27b8bce5fcbe6.

Observed AL5 reply bodies include 201 occurrences of 76 00 78, 179 of 76 00 73 and one 76 00 86. These are literal counts, not a completed request/reply state-machine proof. There are no literal duplicate block transmissions and no AL5 7F-shaped negative replies in the reconstructed frames. This capture does not exercise a checksum-error retry or interrupted erase/programming recovery.

Following programming, the captured sequence includes a seed request with the short reply 67 01 37, a later ordinary seed reply and key exchange, then three Mode 3B VIN-fragment writes acknowledged by 7B 01/02/03. These identity writes must remain separate from calibration programming and must not become a default custom-BIN action.

## Offline tooling and next gates

Tools/AL5/analyze_sps_al5_write.py imports a caller-selected classic USBPcap capture with explicit bus/device/OUT/IN endpoints and a gzip utility. It reconstructs short and extended DVI frames without resynchronization, checks DVI checksums and block lengths, preserves network ordering by completing USB record, records failed transfers, matches loader content and optionally compares ordered expanded modules including padding. It exports a private observation corpus in the rehearsal's T/R format; it is not a send plan. Cross-direction wire timing remains unknown.

Four offline tests cover extended-frame fragmentation, corrupt/truncated framing, loader matching and duplicate observations, malformed block sizes and module/padding comparison. The stopped real capture was imported successfully and its module stream matched exactly.

The existing AL5CapturedWriteRehearsal is an EFILive calibration-specific profile (including a different loader and message-size bound). It deliberately remains unchanged and does not accept this SPS full-programming corpus. Next work is a distinct SPS utility interpreter/rehearsal: map the control table and loader's erase/program/verification actions, correlate pending versus terminal replies, derive destination ranges from loader behavior, and qualify any custom-BIN transformation. Independent readback and physical recovery remain unproven; no live writer is enabled by this evidence.


## Independent calibration readback and loader read-capability audit

Fresh PcmHammer 2.0.0 was built from the current checkout using MSBuild, then used its existing AL5 Read Calibration (Mode 0x23) menu with the GT directly connected. The user confirmed SPS closed, ignition ON/engine stopped and 12.57 V; initialization reported 12.44 V. The read completed at 00:43:19 local time with Success. The user saved the result at their selected Stock Tunes path. No security key, RAM upload, erase, flash or memory-write service was used by this reader.

Readback length is exactly 57,304 bytes. Its SHA256 is 140b70ea90cb57c20aaab2d9641d2b7caaa6bf312c89bd9369b27b8bce5fcbe6, identical to the expanded SPS 15183960 module. Byte comparison has zero differences; anchors pass, BE16 word sum is zero, and native stored/computed checksum is 4E35D040. This independently verifies the calibration segment only, not OS/boot/collateral contents. Private comparison receipt: sps_calibration_readback_comparison.json. Fresh executable SHA256: 8d6c771896f6053b77f656489e5079101018dc3f15bbd6c9e98ffdf8f5510c36.

The preserved raw Motorola loader was decoded offline with Capstone 5.0.6 (M68K 020, big endian), using task-local dependencies. Address ranges 0xFF9006-0xFF966B, 0xFF967C-0xFF9A7F and 0xFF9A90-0xFF9F17 decode completely: 3,826 bytes. The remaining 32 bytes are two eight-entry signed-word jump tables at 0xFF966C and 0xFF9A80. Linear decoding through these tables would misinterpret data as instructions; the audit explicitly separates them. This is static disassembly, not execution or a hardware qualification.

Relevant traced boundaries:

- 0xFF9006 is the captured entry; initialization calls 0xFF9910 and initializes reply identity to 6C F0 18 76 80 73.
- 0xFF9A00 sets d7 to 0x36. At 0xFF9B32 the received service byte is compared to d7; mismatch branches back without calling the block handler. Accepted input calls 0xFF95FC at 0xFF9B3A. No Mode 0x23 read dispatch was identified on this path.
- 0xFF95FC handles incoming block data using RAM 0xFF8000. At 0xFF9640 it sets reply length to six; checksum failure sends status 0x77, and the accepted path calls 0xFF9484.
- 0xFF9484 starts with a pending/status reply, examines module type at RAM 0xFF8022 and enters erase/program processing. For module type 1, 0xFF94B6 calls 0xFF9C50, which invokes the flash erase routine 0xFF9BD8 on flash regions. This loader must not be uploaded as a presumed read-only utility.
- Main and block initialization set six-byte status replies. The sender at 0xFF91A0 transmits the reply buffer at 0xFFA200. Internal flash reads include checksum scans (for example 0xFF954A onward), but no arbitrary flash-data response construction was identified.

Private evidence: sps_loader_read_capability_audit.json, sps_loader_disassembly.json/txt and sps_loader_dispatch_tail.txt. The audit found no ready-to-use readback service; that is a bounded negative finding, not proof that every possible reuse or a separately designed read-only loader is impossible. The existing Mode 0x23 reader was not broadened. Reading other flash ranges still requires resolving resident-service permissions or separately building and qualifying a read-only loader; the captured programming kernel does not by itself close that gate. Live AL5 writes remain disabled.

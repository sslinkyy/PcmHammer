# AL5 BIN to SPS mapping and conditional preservation

## Confirmed file mapping

The current PcmHammer Mode 23 calibration BIN has exactly 57,304 bytes and maps directly, byte for byte, to expanded SPS module 15183960. No wrapper is inserted and no offset is removed. The live post-SPS readback and expanded module share SHA256 140b70ea90cb57c20aaab2d9641d2b7caaa6bf312c89bd9369b27b8bce5fcbe6. This validates the calibration region 0x8000-0x15FD7 only.

SPS stores the downloads as gzip files. Those compressed bytes are transport/storage containers, not flash bytes. Expanded OS module 15184109 is 679,828 bytes mapped to 0x20000-0xC5F93. Its metadata contains the inclusive OS range at offsets 0x3E/0x42 and calibration range at 0x46/0x4A. The OS and calibration module type words are at offset 0x22 (1 and 2 respectively).

SPS stages 4,096-byte chunks at RAM 0xFF8000. The final OS/calibration staging blocks have 108/40 zero-padding bytes. The loader's remaining-byte counter determines how many bytes are programmed; padding is not extra calibration/OS content. The Mode 36 additive checksum covers submode, length, RAM address and the entire staged block including padding. The raw module's native checksum is a different check.

## Three checksum boundaries

- GT DVI framing: byte sum including its checksum equals 255 modulo 256.
- Mode 36 transfer: BE16 trailer equals the additive byte sum from submode through data, including staging padding, modulo 65536.
- Flash module checks: the loader requires zero BE16 word sums over the inclusive metadata ranges. The calibration additionally has the independently reconstructed native four-byte CRC/word-balancing field at 0x15FD4. A balanced word sum alone does not establish a valid calibration; the production inspector checks the native field and anchors.

AL5SpsModuleMapping owns module validation and immutable snapshots. AL5SpsOfflineRehearsal reuses it rather than independently interpreting the same module metadata. Wrong module size/type/range, native checksum failures and anchor failures are rejected. A checksum-correct custom calibration can be represented offline, but this does not authorize edits or establish a safe physical write.

## Regions outside the calibration

Under the traced SPS full-programming algorithm, the modeled affected span is 0x8000-0xFFFFF. It comprises the calibration, lower tail, OS module and upper tail:

- Calibration data: 0x8000-0x15FD7, 57,304 bytes.
- Lower tail: 0x15FD8-0x1FFFF, 41,000 bytes, filled with repeating BE16 0x4AFC.
- OS data: 0x20000-0xC5F93, 679,828 bytes.
- Upper tail: 0xC5F94-0xFFFFF, 237,676 bytes, filled with repeating BE16 0x4AFC.

The modeled lower-tail fill includes the marker at 0x1FFFE; the upper-tail fill includes the marker checked at 0xFFFFE. These bytes are replaced by the SPS algorithm, not restored from a backup. A custom writer that promises to preserve those regions cannot silently reuse this behavior. Padding with zero bytes is also incorrect for the flash tails.

No erase/program command for 0x0000-0x7FFF was identified in this loader. That is a static address-coverage finding, not proof that physical erase leaves boot/persistent data untouched. CompareSavedSnapshots requires two explicit saved raw 1 MiB images and reports differences separately for 0x0000-0x3FFF and 0x4000-0x7FFF. It also reports tail bytes the modeled fill would change, and whether the saved after-image matches the modeled affected bytes. It never infers source freshness or physical preservation.

CopyConditionalAffectedBytes deliberately returns only the 1,015,808-byte affected span. It does not create a full BIN by inventing the unknown first 32,768 bytes. Complete OS/tail/protected-prefix readbacks remain missing for this session; omitted data must not be replaced by zeros/FF or marked verified.

## Validation and retained limits

The BCL-only SpsOfflineRehearsalTest compiles the production mapping, inspector and rehearsal without transport classes. It checks module metadata rejection, balanced-but-native-invalid calibration rejection, checksum-correct custom bytes, immutable ownership, staged-padding rejection, modeled 4AFC fill, detection of protected-prefix changes, detection of affected-tail mismatches and rejection of calibration-only inputs as full preservation snapshots. The saved SPS capture still completes with 180 acknowledged blocks and 201 pending replies, and the optional live-readback file matches the saved SPS calibration module exactly.

This is conditional offline modeling. Physical flash geometry, OS/tail readback, interrupted-write recovery, edit authorization and live PcmHammer programming remain unqualified. LiveWriteEnabled and ReadyToFlash remain false. No controller access is part of these tests.

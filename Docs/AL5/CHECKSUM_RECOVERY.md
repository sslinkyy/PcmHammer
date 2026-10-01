# Native calibration checksum — OS 15184109 / calibration 15183960

The four bytes at `0x15FD4–0x15FD7` have been reproduced offline from both
independent stock and live-read PPEI segments. They are two BE16 words:

1. At `0x15FD4`: reflected CRC16 of bytes `0x08000–0x15FD3`, polynomial
   `0xA001` (normal representation `0x8005`), initial value zero, no final XOR.
2. At `0x15FD6`: `(-BE16_sum(payload) - CRC16) & 0xFFFF`, which makes the sum
   of all BE16 words through `0x15FD7` zero.

The CRC excludes both checksum words. Replacing only the last two bytes to force
a zero sum is not sufficient. `Tools/AL5/checksum.py` checks both words and can
write a new, checksum-corrected **offline** segment without overwriting its input.

## Evidence

The existing EFILive editor-memory dump contains the CRC routine at `0xA95D0`.
It processes bytes using:

```text
index = (byte ^ crc) & 0xFF
crc = (crc >> 8) ^ table[index]
```

The table starts at `0xAA610`. All 256 BE16 table entries exactly match the
generated reflected `0xA001` table. The incremental verifier at `0xA960C`
compares the accumulated CRC to a stored word when the end address is reached.
The calibration caller near `0xA96F8–0xA97DA` names start `0x8000` and end
`0x15FD4`; this supports the payload bounds independently of matching the BINs.
The disassembly is offline evidence, not executed on a controller.

`Tools/AL5/emulate_crc.py` now executes the actual extracted routine and lookup
table in an isolated Unicorn M68020 emulator. Twelve cases pass: empty, the
standard CRC vector, all 256 byte values, deterministic random data, and both
full 57,300-byte reference payloads, each with seeds zero and `0xFFFF`.
`CRC_EMULATION_VALIDATION.json` records source/code/table hashes, instruction
counts and firmware/Python results. Execution is confined to the CRC routine;
no peripheral or vehicle transport is present. This strengthens the first-word
implementation evidence without claiming a third native calibration reference.

Stock SHA256 `140b70ea90cb57c20aaab2d9641d2b7caaa6bf312c89bd9369b27b8bce5fcbe6`:
CRC `4E35`, payload BE16 sum `E18B`, compensation `D040`, complete field
**`4E35D040`**. Full-segment sum is zero.

PPEI SHA256 `d0bcce91cea041bcf82317c73708c2289c78064aa542d6a63c12d3d6d78adc3f`:
CRC `DAE2`, payload sum `69F0`, compensation `BB2E`, complete field
**`DAE2BB2E`**. Full-segment sum is zero.

`CHECKSUM_VALIDATION.json` preserves hashes, computed/stored fields, full lookup
table agreement, and the additional-container search results. CRC32, simple
BE32 sums, alternating word sums, and the tested Fletcher variants do not
reproduce the field; see `OFFLINE_EVIDENCE.json` for those specific tests.

## Limits

The first word has direct firmware evidence and two independent full-segment
matches. The second-word formula is inferred from the known native fields and
the whole-segment invariant; its generating routine has not been isolated.
34 existing COZ files were examined for standard zlib-contained segments; no
additional complete segment was extracted by that limited method. This does
not establish anything about those containers' validity. Additional valid
EFILive-produced edited segments remain a valuable independent check.

Scope is this OS/calibration family. Do not generalize it to every AL5 OS or
to whole flash images. Offline checksum correctness does not establish erase
geometry, programming protocol, recovery, or successful controller acceptance.
No candidate is flash-ready while those remain unknown.

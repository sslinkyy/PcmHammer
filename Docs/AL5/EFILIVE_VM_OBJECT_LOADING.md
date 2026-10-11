# EFILive VM object loading - static evidence

The installed `EFILive_VM.dll` is a 32-bit native library with SHA256
`132832f80d7e5b642033fafc35df4ff3c0f3b19371081d23eacf696c4019ac00`.
Ghidra 12.1.4 analysis recovered the exported `vmLoad` path without executing
the library or an object. [The static record](EFILIVE_VM_OBJECT_LOADING.json)
retains REA Evidence IDs, artifact identity, analysis profile, pseudocode and
limitations. Full provider Evidence remains in the local investigation bundle,
outside Git. This does not establish the host callback implementation.

## Observed load boundary

`vmLoad` at `0x40B448` calls the file loader at `0x40315C`. It reads a
16-byte header, seeks to the offset at header+2, reads the length at header+4,
then seeks to header+6 and reads the length at header+8. These are little-endian
16-bit fields in the native x86 load path. The sizing helper at `0x403344`
clamps code/data lengths to `0x2E00` and `0x3E00` respectively.

The code transform starts 42 bytes into its section and excludes that preamble;
the data transform covers its whole section. The transform helper at `0x403060`
uses 4096-byte chunks and selectors `0x0C`/`0x0D`. It invokes the callback stored
at `0x4398A0` before local word transformation. `vmCallback` at `0x40B2AC`
sets this pointer from caller callback-table+4; it sets `0x4398A4`, used in
validation at `0x403380`, from callback-table+8. Callback results influence
success/error paths and the code's initial checksum-byte comparison.

The local transform at `0x40BD8C` requires four-byte alignment. It processes
32-bit words through thirteen iterations of `0x40BB98`, using table selector 2,
then XORs the byte-swapped table word and chunk-local word index. The selected
word is observed as `0x958E3535` at `0x41D0D4`. This recovers the local operation;
it does not reproduce the callback operation that precedes it. Applying only
the local operation does not establish valid VM instructions or object CRCs.

## Offline PcmHammer extension

`Tools/AL5/inspect_vm_objects.py` checks the four installed AL5 object layouts
and emits offsets, lengths, original unknown header words and section hashes.
It intentionally rejects oversized declarations instead of copying the native
reader's clamping behavior, and rejects overlapping, truncated, trailing or
unaligned sections. [The inventory](EFILIVE_VM_OBJECT_INVENTORY.json) records
all four inputs. No section bytes are exported and no callback is called.

Reproduce with `--object <AL5_R.obj> --object <AL5_F.obj> --object <AL5_L.obj>
--object <AL5_W.obj> --output <new-report.json>`. Existing output and input files
cannot be overwritten. These are proprietary VM objects, not established raw
controller loaders. Do not upload them or treat framing as executable decoding.

Next trace the host registration and implementation of callback-table+4/+8
using this library's explicit call boundary, then validate transformed sections
against the actual checksum operation. The callback's relationship to HAPI or
EFILive device hardware is still unknown. No EFX decoder or recovery claim is
established by this evidence. The planner hash-links both static evidence and
object inventory, and keeps write readiness false and packet lists empty.

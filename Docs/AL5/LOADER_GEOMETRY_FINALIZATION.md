# Saved finalize pointers and conditional flash geometry

[The report](LOADER_GEOMETRY_FINALIZATION.json) links the saved LOW/HIGH images
by SHA256. It records static loader observations and a published candidate chip
layout; no code from the loader was executed and no hardware was contacted.

## Finalization range

The saved HIGH image at CPU address `0x20046` contains start `0x8000` and inclusive
last-byte `0x15FD7`. The routine at `0xFF91D6` subtracts one from the latter,
sums BE16 words before `0x15FD6`, then adds the final stored word modulo 65536.
This checks the zero word sum over exactly 57,304 calibration bytes. It does not
recompute the native CRC16. A synthetic regression preserves this sum while
invalidating the native CRC, demonstrating that the two checks are distinct.

The saved calibration has a zero sum and a valid native checksum. The saved LOW
image contains `0x4AFC` at `0x1FFFE`, matching the static completion-marker write.
Neither observation proves current physical state, successful past programming,
capture completeness or recoverability. These editor-memory images are not a
current physical backup.

## Conditional manufacturer geometry

Update 2026-10-10: [owner-supplied physical photographs](PHYSICAL_HARDWARE_20261010.md)
now identify Am29F800BB in the truck's module. The CPU mapping, bus width,
protection state and preservation assumptions below remain unverified; the
photographs do not turn this report into an executable erase plan.

The [AMD Am29F800B datasheet](https://www.batronix.com/files/Datenblaetter/29__/AM29F800B.pdf),
document 21504E5 dated November 2, 2006, Table 9 associates manufacturer `0x01`
and word device ID `0x2258` with the bottom-boot part. Table 3 places byte-address
sectors at `0x8000–0xFFFF` (32 KiB) and `0x10000–0x1FFFF` (64 KiB).
The x16 chip word-address coordinates are half the CPU byte-address coordinates.
This is consistent with the loader's ID constants and erase-call addresses.
It does not identify the installed chip or establish physical mapping.

Under that conditional mapping, the erase span is 98,304 bytes. Calibration
occupies 57,304 bytes; the remaining 41,000 bytes at `0x15FD8–0x1FFFF` include
the completion marker. A calibration-only BIN cannot preserve this collateral.
The saved report hashes the collateral but marks current backup verification
false. Persistent banks at `0x4000`/`0x6000` sit outside these sectors; earlier
application boot-preparation evidence still shows separate updates to those banks.

## Reproduction and next work

Run `Tools/AL5/analyze_loader_geometry.py --low <saved-low> --high <saved-high>
--output <report>` using the existing private dumps. The report contains metadata
and hashes only. The dry-run plan hash-links it and retains null erase scope,
false readiness and empty packet lists.

Next model the captured loader parser with flash and MMIO calls trapped, starting
with zero/odd counts, address bounds and malformed buffers. Establish physical
identity, preservation, complete acknowledgments and recovery independently
before a live writer can be considered. Do not upload or replay this loader.

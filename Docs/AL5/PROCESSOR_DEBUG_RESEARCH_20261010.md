# AL5 processor marking and conditional debug-interface research

Recorded 2026-10-10. This continues the owner's actual truck-module photographic
evidence in [the hardware note](PHYSICAL_HARDWARE_20261010.md). No adapter,
debugger or controller was opened or operated during this research.

## New photographic evidence

Two additional original closeups show the large square IC beside the AMD flash.
The numeric marking `09360403` is readable. The smaller lines appear to be
`H83W` and `UC0E4024`, but those transcriptions remain provisional. Do not
assign manufacturer mask, date, lot or ordering-code meanings without a
documented match. The earlier broader photo showed a Motorola-style logo.

Exact-number and apparent-mask searches did not find a reliable public
manufacturer cross-reference, an AL5-specific internal debug-pad map, or a
demonstrated BDM read of this hardware. This is a search outcome, not evidence
that such documentation or access does not exist. Generic component listings
without a datasheet or cross-reference do not establish processor identity.

## Existing offline evidence is a candidate, not identification

The saved loader and startup disassembly already support Motorola 68000-family
code. The existing [FIFO/register comparison](FIFO_CANDIDATE_COMPARISON.md)
conditionally interprets startup stores at `FFFA54` and `FFFA56` using the
MC68336/376 SIM register map. Neither instruction compatibility nor matching
register offsets distinguishes the exact fitted MCU or its package pinout.
The new photographs do not promote that candidate to confirmed identity.

## Manufacturer debug documentation found

- [AN1230: Background Debugging Mode Driver Package](https://www.nxp.com.cn/docs/en/application-note/AN1230.pdf),
  pages 1-4, documents CPU16/CPU32 BDM, interface circuitry and driver functions.
  For CPU32 it names `BKPT/DSCLK`, `IFETCH/DSI` and `IPIPE/DSO`, plus reset,
  freeze indication and power/ground references. Its recommended 10-pin header
  is a generic connector convention, not the AL5 board's pad order.
- [MC68336/376 development support](https://www.nxp.com/docs/en/user-guide/MC68336376UMC.pdf)
  is a manufacturer reference for that candidate family, not a cross-reference
  for the photographed `09360403` marking.
- [NXP MC68376 resources](https://www.nxp.com/products/MC68376) list
  `BD32-122DBG`, Background Debug Monitor for 68300 Parts. Listing availability
  does not establish compatibility with this chip, a modern USB probe or host
  OS. The package was not downloaded or executed for this note.

AN1230 explicitly gives the debug host control over registers, memory, reset
and execution. A memory-read objective therefore does not make an arbitrary
debugger startup script non-mutating. BDM acquisition needs a separate reviewed
procedure; it is not a substitute for the existing Mode 0x23 reader today.

## Evidence required to advance

1. Match the actual marking to an authoritative MCU identity, or obtain an
   independently verified board-specific pinout. Record package and pin-1
   orientation as part of that match.
2. With the module unpowered and disconnected, map candidate pad continuity to
   the verified MCU debug pins and ground. Retain measured results and photos;
   a pad's shape or row position is not an assignment. No MCU pin numbers or
   board pad numbers are assigned in this document.
3. Verify target logic voltage and the selected probe's CPU32 support, input
   voltage tolerance, power behavior and reset handling before connection.
   A product labeled BDM is not sufficient compatibility evidence.
4. Review the exact startup script for reset, RAM/MMIO writes, uploaded code and
   flash initialization. Establish a separate bounded acquisition plan before
   any powered debug experiment. No connection or reset is authorized here.
5. If acquisition becomes validated, retain repeated matching full-chip dumps
   and compare known calibration anchors to the existing direct-read BIN.
   A matching dump proves acquisition consistency, not programming or recovery.

Current blockers are MCU cross-reference, pad mapping and verified probe setup.
The working Mode 0x23 path and all write gates remain unchanged.

## Original-photo provenance

Originals remain local and are not committed. SHA256:

- `1-1000021054.jpg`: `4d43bb0e01bbbdbf6c919cee130234d353146fb976ab9800f6ce5bc00c419680`
- `1-1000021055.jpg`: `c48985d67cf17a55f614415e8949f9966c92d9fcb00d091538b51e70973d38a6`

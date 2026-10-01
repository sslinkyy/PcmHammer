# Receive classification and boot preparation — offline evidence

Thirteen isolated cases now execute the selected receive classifier and the
application boot-preparation caller. Every storage/subsystem implementation is
intercepted with an explicit return stub; no flash erase/program routine is
loaded or executed. No live seed/key, boot entry, reset or vehicle I/O occurred.

## Receive state is derived from header bits

The routine at 0xC1034–0xC10BD reads the request at 0xFF8EB6 plus the byte offset
at A5+0xEFF. It constructs an index from bit zero of request byte one (weight
four), bit zero of byte two (weight two), and bit six of byte four (weight one).
The saved table at 0xC10BE maps indices 0–6 to `0,3,0,0,1,2,1`; index seven
uses fallback state three. The result is stored at A5+0xF2A.

All eight combinations and a nonzero receive offset are exercised. The tested
internal header 6D/18/F0/34 gives state one; the linked descriptor call with
argument one reaches the existing boot-request handler, as previously traced.
The classifier alone does not validate destination, length, physical CRC,
full receive routing, queue ownership or timing. It must not be treated as a
frame-acceptance test. State/offset initialization elsewhere remains open.

Application RAM context overlaps the addresses used by boot upload flags.
The new observations deliberately omit inherited boot-only arming labels:
application bytes at those addresses cannot be interpreted through the boot
layout. This prevents arbitrary synthetic context bytes from being mistaken
for an armed loader.

## Boot preparation has persistent-storage side effects

The routine at 0x5BAB8–0x5BB6D is called before the application's final interrupt
mask/0xBFC1 marker/spin sequence. Its extracted instructions:

1. Save the current status through 0x21D08 and mask interrupts.
2. Feed the watchdog through the long-address register 0xFFFFFA26, preserving
   its high byte while writing low bytes 0x55 then 0xAA.
3. Call ten subsystem helpers, including one that examines security-related state.
   Their implementations remain stubbed and are not assigned complete effects.
4. Execute the known CRC routine over RAM A5+0x140 through A5+0xB30 exclusive
   (2544 bytes), seed zero, storing the resulting word at A5+0xB30.
5. Invoke storage-update caller 0x226F0 with source argument 0xFF8140.
6. Restore the saved status through 0x21D18 if the stubbed calls return.

The standalone test confirms status restoration, watchdog writes and call order.
Linked locked/unlocked request cases verify that the tested security rejection
prevents preparation, while an accepted callback reaches the storage stub.
The RAM-context CRC matches the Python reference. Stubbed subsystem operations
do not reproduce the actual complete context contents or storage result.

Static tracing of 0x226F0–0x228D7 shows selection between starts 0x4000 and 0x6000,
generation counters and header/data updates. It calls 0x22B18, whose copied
routine issues flash unlock/erase writes, and uses 0x22C3C for word programming
and comparison. Those routines are **static evidence only**; the emulator stops
at the 0x226F0 stub and never enters them. The stub return is not evidence that
a real update succeeded or that the caller can safely proceed after a fault.

This matters before calibration programming: application boot entry can reach
persistent flash updates outside 0x8000–0x15FD7. A calibration-only backup does
not establish preservation for those side effects. Bank starts do not prove
physical erase geometry, chip identity, endurance or interrupted-update recovery.
The earlier inferred 41,000-byte calibration-sector collateral remains a
separate unresolved preservation issue; these starts are not added to an
executable erase plan or treated as an independently verified byte count.

## Reproduction and limits

`emulate_receive_preparation.py` extends the existing protected emulator with
only the classifier, preparation caller, real status restore and known CRC code.
Synthetic MMIO models the long-address watchdog register; its physical aliasing
and timing are not emulated. ROM stays read-only, unexpected execution fails,
and source hashes are required. No flash-storage implementation is present.
`RECEIVE_PREPARATION_EMULATION.json` contains assertions and per-step records;
`RECEIVE_PREPARATION_STATIC_EVIDENCE.json` contains bounded supporting disassembly.

The file-only planner includes a hash-linked preparation assessment and a
distinct persistent-storage preservation blocker. Backup sufficiency, storage
geometry and physical boot entry remain unverified; readiness is false and all
packet lists stay empty. The direct reader and hard live-write block are unchanged.

Next recover the storage-bank selection/update/recovery policy statically and
the receive-buffer lifecycle, then complete reset/boot timing and loader ABI
evidence. Do not probe application boot entry experimentally on the only TCM.

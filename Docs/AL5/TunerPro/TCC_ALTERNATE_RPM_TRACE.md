# Alternate TCC minimum-RPM inhibit: 0x145E0 / 0x145E2

Offline trace, 2026-11-03; saved AL5 OS 15184109 / calibration 15183960.

## Findings

The alternate pair belongs to an **active shift/transition-control state**.
It is selected when runtime byte A5+0x2D1D equals 1. All other byte values
use the marker-confirmed D5057/D5058 pair at 0x1375C / 0x1375E. The selector
is separate from the Normal/Tow-Haul and cruise table-bank selectors.

Both pairs are unsigned BE16 RPM counts with the shared /8 conversion:

- 0x145E0 = 7200 raw = 900 RPM, used when the inhibit latch was clear.
- 0x145E2 = 8400 raw = 1050 RPM, used when the inhibit latch was nonzero.
- Stock 0x1375C / 0x1375E have exactly the same values.

Therefore the selection makes no threshold difference in the stock reference.
Synthetic changes restricted to emulator memory prove that state 1 uses the
alternate addresses independently of the ordinary pair.

## What selects them

A5+0x2D1D is initialized to 3. It is a state in the transmission transition
controller, not simply a driver mode. The producer at 0xB553C-0xB56AE accepts
a new transition request through changed-request flag A5+0x2F51 and requested
state A5+0x2D12. The changed-request flag is derived from requested word
A5+0x26B4 versus previous word A5+0x2694 and associated control-triple
changes in 0xBB274-0xBB2F4.

The requested state is loaded from byte 4 of a selected 16-byte transition
descriptor. The descriptor lookup at 0x33776 uses encoded old/new range
values A5+0x26BE and A5+0x26B4, lookup helper 0x339CC, matrix 0x33AB0, and
descriptor pool 0x34540. Related descriptor fields select clutch-control
parameters, corroborating its transmission-transition role.

The complete saved 52x52 matrix references descriptors requesting only state
0 or state 2. None requests state 1 directly. This is an inventory of matrix
contents, not proof that all 2704 combinations are physically reachable.

Without a fresh request, state 0 advances to state 1 when A5+0x2E16 clears.
State 1 stays active or advances according to the transition completion
fields: with A5+0x2D7A other than 3, completion byte A5+0x2D95=1 advances to
state 2, and value 2 returns to state 0; A5+0x2D7A=3 holds state 1. State 2
advances to state 3 when A5+0x2E16 clears. Other request/branch cases are
retained in the selector evidence.

Independent semantic corroboration links state 1 to the desired-shift-time
work through 0xBCE90, 0xC2FF8 and its inner bridge at 0xC305E, wrappers
0xC58F8/0xC58E4/0xC58F0, and 0xC5674/0x83AF4.
That calculation consumes the base/correction fields corresponding
to previously mapped D5080 shift timing (0xDC68 / correction 0xE248).
This supports an active shift-control phase. An exact hydraulic label such
as fill, torque transfer or inertia phase has **not** been established.

## Hysteresis and lockup effect

The input is the filtered RPM word A5+0x1214. Its producer uses getter
0x29A30 (A5+0x1E6C) and filter 0xB94E8 with calibration 0x14B36. The
threshold conversion follows the independently marker-confirmed ordinary
RPM definitions and the identical consumer; no new sensor measurement was
made here.

At 0xA3E3A the code chooses the pair and updates the **shared** inhibit
latch A5+0x1F14:

```text
pair = alternate if byte(2D1D) == 1 else ordinary
threshold = pair.high if old_latch != 0 else pair.low
new_latch = unsigned_RPM_raw < unsigned_threshold_raw
```

The comparison is strict. With stock values:

- With a clear latch, RPM below 900 sets the inhibit; exactly 900 does not.
- With the latch set, it stays set below 1050; exactly 1050 clears it.
- In the interval 900 through just below 1050, the previous latch state matters.
- The latch carries across pair changes; the routine does not reset it on a
  transition into or out of state 1.

When the inhibit is set, the consumer normally clears bits 5 and 2 and sets
bit 7 of A5+0x2402. There is a specific exception: if current TCC state
A5+0x2407 is 7 and calibration byte 0x145B6 is zero, this particular low-RPM
override is bypassed and later logic continues. The stock byte is 1, so the
inhibit is enforced even for state 7 in this reference.

The resulting downstream chain is:

1. 0x87924 gives bit 7 highest priority and selects request A5+0x2406=0.
2. 0x3AAD4 sees request 0 and sets bit 6 of A5+0x240E, release reason index 1
   in the 28-bit reason bitmap.
3. 0xADAA8 / helper 0xA9BF0 can select TCC state A5+0x2407=0 when that reason
   is present, subject to the existing diagnostic/other arbitration overrides.
4. The previously traced state-0 command path normally produces zero in
   internal command 0x23CA at ordinary road speeds; its speed hysteresis,
   overrides and physical-output boundary remain described in
   `TCC_RELEASE_ARBITRATION_20261102.json`.

Clearing the RPM inhibit only allows later lockup logic to proceed. It does
not force engagement: speed, slip, temperature, transition state and other
requests/reasons still participate. Raising either alternate threshold can
extend this low-RPM restriction specifically while state 1 selects that pair;
the hysteresis and previous latch state determine when it changes. This is a
software consequence, not a tested calibration recommendation.

## Evidence and validation

- `TCC_RPM_SELECTOR_20261103.json` and
  `Tools/AL5/trace_tcc_rpm_selector.py`: bounded direct-reference inventory,
  transition descriptors/matrix, state producer, and real extracted-code
  descriptor/state replays (31 passing cases). Exact physical phase terminology remains unknown.
- `TCC_RPM_SELECTOR_NAMED_ANCHOR_20261103.json`: complementary byte-bound
  call/data windows, native-help provenance and named shift-time definitions.
- `TCC_ALTERNATE_RPM_EFFECT_20261103.json` and
  `Tools/AL5/trace_tcc_alternate_rpm.py`: 160 extracted-code cases exercising
  unsigned raw boundary values, prior latch 0/1/255, selector states
  0/1/2/3/255, isolated alternate-pair markers, and state-7 enforcement.
  RAM is carried through the actual inhibit, request-priority, off-reason and
  arbitration routines. No call stubs are used.
- The marker cases temporarily use 1100/1250 RPM in the alternate pair inside
  emulator memory. They change state-1 results while other selector values
  continue to use 900/1050. Original files remain unchanged.
- Replays use RX firmware memory and synthetic runtime RAM, explicit code
  bounds, instruction limits, exact program-counter completion and balanced
  stack checks. They do not replay the whole scheduler or qualify physical
  timing, hydraulic response or controller acceptance.

Source SHA-256 values:

- Low dump: `cf5dd139e52ba5925fc95f166627a9a7abcac1374ded8cb738df8297b961a3f6`.
- High dump: `492040d9460d53b77dda606b9a89f4254e0680f239093001663f6ed5cf51ba75`.
- Stock segment: `140b70ea90cb57c20aaab2d9641d2b7caaa6bf312c89bd9369b27b8bce5fcbe6`.
- PPEI segment: `d0bcce91cea041bcf82317c73708c2289c78064aa542d6a63c12d3d6d78adc3f`.

All source BIN identities were checked after the investigation. No vehicle
I/O, source BIN writes, XDF changes or live reader/writer changes were made.

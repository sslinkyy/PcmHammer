# Alternate TCC throttle-release families: cruise-conditioned selection

Offline investigation started 2026-11-02 and verified 2026-11-03. Target:
AL5 OS 15184109 / calibration 15183960. Original calibration and firmware BINs
were read only. Synthetic changes below exist only in isolated emulator memory.

## Result and tuner significance

The extra families are cruise-conditioned alternatives to the named TCC
throttle-release tables:

- **0x13A08 header: Tow/Haul alternate**, alongside named D5074 at 0x13950.
- **0x13C30 header: Normal-family alternate**, alongside named D5073 at 0x13B78.
- Mode 2 keeps D5075 / 4WD Low at 0x13AC0 regardless of the alternate flag.

These are analyst-derived names, not newly discovered EFILive IDs. Selection,
layout, interpolation and the software comparison are established from saved
firmware. Cruise semantics are corroborated by the decoded CCVS message fields
and manufacturer J1939 documentation. The Normal label follows the existing
marker-confirmed base-family mapping; the selector's other-mode branch is not
proof that every possible mode value means Normal.

Both alternate families and their Normal/Tow base counterparts contain only
0xFFFF in the stock reference. Consequently switching between each base and
alternate bank does **not change the lookup result in stock calibration**.
They nevertheless provide separate cruise-conditioned calibration locations.
Their value is a maximum-throttle release parameter, not an instruction to
unlock whenever throttle rises above it. The local EFILive help describes
D5073-D5075 as maximum throttle to release TCC in their respective modes.

In the traced path, 0xFFFF is an ordinary numeric value (99.99847412109375%
under the established fixed-point conversion), not a special disable opcode.
Changing a bank can change a release-related software reason under the other
gates. It does not directly command a solenoid or guarantee a physical unlock.

## What activates the alternate banks

The descriptor at 0x6FDD0 contains `0102004020FEF100`. The message dispatcher
uses its handler index 2; table entry 0xBCA58 points to decoder 0xBAB80.
That decoder separates these CCVS / PGN 0xFEF1 fields:

- Payload byte 7, bits 8-6: cruise state, stored at A5+0x2125.
- Payload byte 6: cruise set speed, converted into A5+0x2122.
- Payload bytes 2-3: wheel-based vehicle speed, stored separately at A5+0x1CB0.

Those bit positions match [PCS J1939 documentation, page 6](https://powertraincontrolsolutions.com/download/Released/Public/Developer_Files/PCS%20J1939%20Messages%20v2_1.pdf).
[Danfoss's CCVS1 receiver documentation, page 26](https://assets.danfoss.com/documents/latest/67498/AQ310885477127en-000101.pdf)
corroborates SPN 86 set-speed units (km/h) and SPN 527 state meanings. These
sources identify the protocol fields; they are not evidence that the truck
actually transmitted a frame during this investigation.

With stock source configuration, routine 0xB6BE4 produces active flag
A5+0x2120 for valid states 1-5 (hold, accelerate, decelerate, resume, set).
Off state 0, accelerator override 6, and invalid/unavailable state handling
do not enable it. Incoming state 7 retains the prior stored state but sets an
invalid bit that prevents treating it as active through this stock path.

Routine 0x4ABCC sets A5+0x1226 only when all of these hold:

1. The active flag above is nonzero.
2. Unsigned throttle-like word A5+0x1DB2 is <= calibration 0x14B4C.
3. Filtered vehicle-speed word A5+0x120C is within the inclusive, saturated
   interval `[A5+0x120A - cal14B48, A5+0x120A + cal14B46]`.

Stock 0x14B4C is 0xFFFF, so that input cap imposes no further restriction on
an unsigned 16-bit input. Both speed margins are 0x0500: 1280 raw counts,
corresponding to approximately 10 km/h each with the corroborated /128 speed
scale. A5+0x120A is the cruise-set-speed-derived reference after a learned
normalization, not necessarily the unmodified displayed set speed. Its fault
fallback can copy A5+0x120C; whole-controller freshness/fault handling was not
qualified by this bounded replay.

The family selector at 0x3A83C then uses:

- Mode 1 + flag1226 + byte0x11ACC nonzero -> 0x13A08; otherwise 0x13950.
- Mode 2 -> 0x13AC0.
- Other modes + flag1226 + byte0x11ACD nonzero -> 0x13C30; otherwise 0x13B78.

Both enable bytes are stock 1. Cruise does not itself force Tow/Haul: the
separate cruise mode-override byte 0x15307 is stock 3 (fall through).

## Axes, layout and scaling

Each family has five records. Each record is a 0x0011 BE16 count followed by
17 unsigned BE16 cells; record stride is 0x24 bytes. Data address is
`family_header + 2 + 0x24 * column`. Thus each family has 85 values, and the
two extras contain 170 values in total. File offsets in the 57,304-byte
calibration segment are native addresses minus 0x8000.

Column indices 0-4 share the marker-confirmed labels first through fifth gear.
They use A5+0x2286, committed from selected/candidate gear state A5+0x2250 at
0xC06E6. This is not a measurement proving that the physical gear is achieved.

The row input is filtered speed A5+0x120C. Actual helper 0x3DC40 reads axis
`[2, 0, 32768]` at 0xBF2E4 and returns `min(2 * raw_speed, 65535)`.
The 17 raw breakpoints are 0, 2048, ..., 32768. Shared native D5073 labels are
0, 16, ..., 256; vehicle speed in km/h with raw/128 is a corroborated
interpretation from those labels, the speed producer and the network scaling.
The native export itself does not carry an explicit row-unit field.

Actual helper 0x3DD40 interpolates unsigned cells using a 12-bit fractional
coordinate. It truncates the delta magnitude toward the first endpoint.
At/above the last speed breakpoint the coordinate is 65535: a varying last
segment approaches, but need not exactly reach, the final cell. Constant
0xFFFF vectors still return 0xFFFF throughout.

Cell display scaling is `percent = raw * 100 / 65536`, inherited from the
marker-confirmed D5073-D5075 representation and supported by the identical
lookup/consumer path. It is not `raw / 65535 * 100`.

## Actual software effect

The encompassing routine is 0x3A7C0-0x3A9B8. It first requires bit 1 of
A5+0x23FA and a signed acceleration-like hysteresis gate in A5+0x23FE bit 6.
The latter compares filtered speed derivative A5+0x1212 with stock raw limits
614 / 2458 at 0x14E38 / 0x14E3A, selected by the previous gate state. The
comparison is strictly less-than. Physical acceleration units and task period
remain unqualified.

After selecting/interpolating the throttle-release vector:

```text
T = interpolated unsigned table value                         -> A5+0x23C4
R = axis_3DC40(0x150EA, A5+0x1CE4)                           # RPM coordinate
S = surface_3DF08(0x14E48, R, T)                             -> A5+0x23B6
G = BE16(0x14E3C + 2 * selected_gear_index)
P = (S * G) >> 19                                           # 0x13 = 19
Q = saturate_u16(((P & 0xFFFF) * A5+0x155E) >> 12)           -> A5+0x23B4
if Q > unsigned_word(A5+0x1544):
    A5+0x2410 |= 0x02
```

The 0x14E48 surface is unsigned, 17x17, column-major; the helper performs
bilinear interpolation. Its RPM axis has 17 points, 200 through 3600 RPM
using raw/8, with nonuniform spacing. The runtime comparison quantity 1544
has several producer branches. Its ordinary source 154A uses the same surface
with the live throttle getter (`0x299F0 -> 0x97868 -> A5+0x1DB2`), gear factors,
and additional compensation. That is why this is not universally equivalent
to comparing the pedal directly against T. The stock 0x14E18 setting gives
155E=4096 (unity), but another runtime factor 1602 affects the ordinary
comparison-quantity producer and is absent from the threshold path.

The setting operation is an OR. This routine does not clear an already-set
reason when a gate later fails. The broader lifecycle clears the reason bitmap
elsewhere, including the 0x8780C initialization path. The extracted tests check
both fresh and pre-existing reason states.

Concrete synthetic example: at raw RPM 16000 (2000 RPM), selected fifth gear,
unity 155E, and active prerequisite gates, constant table values 0%, 25%, 50%,
75%, and approximately 100% produce internal comparison thresholds 0, 74,
307, 595, and 733 respectively. These are internal counts, not independently
qualified torque units. A runtime comparison value 400 would meet the release
reason test for 75%/approximately 100%, but not 0%/25%/50%. Equality does not
set the bit. These are emulator examples, not tuning recommendations.

Reason 0x2410 bit 1 is bit index 22 in the 28-bit bitmap beginning at 0x240E.
The downstream arbitration path scans that bitmap and can select state 0 at
A5+0x2407 when any reason is present, subject to earlier overrides. The real
arbitrator 0xADAA8 was replayed with reason index 22, no reasons, and an earlier
2419 override; that override can bypass the reason. State 0 dispatches to
0x3FACC, which clears 23DA/DC/DE and uses speed hysteresis to choose internal
command quantity 23CA=0 or 23CA=23CE. Stock speed thresholds are raw 32512 /
32640 (254 / 255 km/h under the corroborated scaling). Ordinary road-speed
cases therefore reach zero in that internal command quantity. Diagnostic
overrides and later output conversion remain outside this claim; it must not
be equated with unconditional zero PWM duty or a physically observed release.

## Evidence and reproducibility

Source identities:

- Low editor dump, 0x00000-0x1FFFF:
  `cf5dd139e52ba5925fc95f166627a9a7abcac1374ded8cb738df8297b961a3f6`.
- High editor dump, 0x20000-0xFFFFF:
  `492040d9460d53b77dda606b9a89f4254e0680f239093001663f6ed5cf51ba75`.
- Stock calibration segment:
  `140b70ea90cb57c20aaab2d9641d2b7caaa6bf312c89bd9369b27b8bce5fcbe6`.

The low editor image and stock segment are distinct artifacts. The effect
replay explicitly overlays the exact stock calibration into emulator memory;
the original files remain unchanged.

- `TCC_ALTERNATE_FLAG_PRODUCERS_20261102.json`: protocol/flag/mode windows,
  42 extracted-code cases, and bounded direct-reference inventory.
- `TCC_THROTTLE_AXES_20261102.json`: axes, column commits, unsigned vector and
  bilinear lookup windows; 478 extracted-code cases. Repeated after adding an
  explicit program-counter completion check; the semantic results matched.
- `TCC_THROTTLE_EFFECT_20261103.json`: actual containing routine with real
  getter and interpolation helpers, 115 cases covering mode/gear selection,
  synthetic table values, strict comparison edges, compensation, gate
  boundaries and preservation of pre-existing reasons. No call stubs.
- `TCC_RELEASE_ARBITRATION_20261102.json`: reason bitmap and downstream state
  path, plus comparison-input and speed-derivative producers; 14 real-code
  cases covering first-set-bit scan, arbitration/bypass, and state-0 speed
  hysteresis.
- `MARKER_VALIDATION_v0_9.md`: independent native identities of the base
  families, their cell conversion, and preserved distinction for the extras.
- Local `C:\Car Tuning\AL5_15184109.html`, D5073-D5075 entries: native parameter
  descriptions. Native export hash is retained in the axis report.

Reproduction scripts are `Tools/AL5/trace_tcc_alternate_flag_producers_20261102.py`,
`trace_tcc_throttle_axes.py`, `trace_tcc_throttle_effect.py`, and
`trace_tcc_release_arbitration.py`. Each accepts explicit input and report paths;
use an absent output path. Existing local Capstone/Unicorn dependencies were
used. M68020 emulation of these saved instruction windows does not establish
the exact physical CPU or full-controller timing.

## Remaining boundary

The table identity, selecting condition, raw axes, interpolation and bounded
software effect are now substantially resolved. Remaining unknowns are full
scheduler/fault/freshness behavior, calibrated physical units for intermediate
modeled quantities and the acceleration signal, and the hydraulic outcome in
an operating transmission. No XDF defaults, source BIN, live read/write code,
controller state or vehicle hardware was changed. This is not flash-readiness
or physical-validation evidence.

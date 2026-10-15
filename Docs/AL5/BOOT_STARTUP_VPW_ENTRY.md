# AL5 startup and VPW receive entry

Four additional file-only models connect saved startup and interrupt-handler
code to the existing marker and resident-service models. They do not connect
to an adapter, load a controller kernel, erase or program flash. PcmHammer's
AL5 live-write rejection remains enabled; the working Mode `$23` reader is
unchanged.

## Application integrity startup

`emulate_calibration_startup.py` executes the original ROM-copy loop. It copies
312 bytes from `0xC5E4A..0xC5F82` into `0xFF8008..0xFF8140` and clears the
following RAM range. ROM `0xC5F46` supplies initial-check flag 1 at `0xFF8104`;
ROM `0xC5F48` supplies CRC seed 0 at `0xFF8106`. Two initial RAM fills produce
the same flag and seed. This copy-only model treats watchdog stores as
synthetic emulated memory effects, not physical peripheral operations.

`emulate_calibration_initializers.py` continues the actual pre-marker
initializers through `0x994F8` in the same emulated RAM session. All watchdog
and timer MMIO instructions are suppressed before execution. Three synthetic
timer contexts preserve flag 1 and seed 0 and establish RAM marker `0x0595`.
Separate marker-check sessions transfer those three observed values: a valid
calibration preserves `0x0595`, an erased completion marker produces `CC8B`,
and payload corruption produces `30D4`. The existing separately selected boot
branches remain conditional routes, not observed resets.

Earlier apparent invalid operands are valid 68020 full-format addressing.
The original LEA at `0xC5B54` computes `0x20410` from A5 and a long displacement;
the actual MOVEC instruction receives that value as its vector-base source.
No opcode patch is used. Unicorn 2.1.4 does not provide defined VBR readback
through its register API, so register acceptance remains explicitly unverified.
These bytes do not support the earlier suggestion that local startup source
was missing.

## Resident boot receive path

`emulate_boot_interface_gate.py` starts after hardware word read `0xFFFD02`.
Across 261 synthetic words, the original comparison sets `0xFF8010` when the
word's low byte is at most decimal 20. It then tests the real conditional call
to `0x3B7C` and executes the selected idle interrupt-mask sequence to `0xE80`,
where the software mask is zero. The hardware register's meaning, preceding
readiness loop and omitted initializer effects remain unknown.

Static boot code selects VBR zero; vector offset `0x6C` names ISR `0x39AC`.
This differs from the application's vector-base source above.
`emulate_boot_receive_isr.py` executes that ISR's original LINK/MOVEM prologue
and epilogue with synthetic FIFO callbacks. Six contexts cover disabled
reception, idle return, resident dispatch, RAM-transfer entry and overflow
flush. Execution stops before RTE, resident dispatcher `0x341C`, or transfer
handler `0x3074`. Neither interrupt delivery nor the hardware FIFO runs.

A test transfers the staged synthetic service `0x34` frame to the existing
resident dispatcher model, which arms upload and constructs logical response
`6D F0 18 74 44`. These are independent slices joined with synthetic input,
not a continuous wire exchange or proof of successful loader upload.

The continuation also identifies `0x2A24` as scheduler RAM initialization and
`0x3E94` as an optional external-RAM service; neither is a proven VPW polling
loop. The native idle loop is interrupt-driven. Physical interrupts, RAM
retention, peripheral configuration and reentry after power loss remain open.

## Application authorization and remaining qualification

A separately saved static trace of application dispatcher `0xA4A38..0xA4C9E`
reaches the Mode `0x34` handler through its service descriptor. Descriptor
`0x9000` does not bypass the handler's lock-bit-5 guard. A locked state must
first clear that guard; an already clear state does not unconditionally
perform another key exchange within this path. Queue acceptance and the
running security state are not modeled.

Source images are saved editor memory, not current physical backups. Models
pin LOW SHA-256 `cf5dd139e52ba5925fc95f166627a9a7abcac1374ded8cb738df8297b961a3f6`
and HIGH SHA-256 `492040d9460d53b77dda606b9a89f4254e0680f239093001663f6ed5cf51ba75`.
Private source windows and generated reports remain under
`Tools/AL5/LocalOnly/VPWRecovery_20261015/`; no proprietary image bytes are
included in the public changes. `CALIBRATION_MARKER_EMULATION.json` is
regenerated for the backward-compatible initial-RAM-marker API.

The user currently has no spare AL5. Qualification therefore remains blocked
on a recoverable matching controller on an isolated bench, a complete physical
VPW entry/upload/program exchange, proven erase scope and collateral
preservation, independent programmed-image readback, and demonstrated
interrupted-flash recovery. Transfer retries and conditional boot routes do
not satisfy those requirements. The installed truck TCM is not an authorized
test target. Physical recovery, automatic retry, live writes and flash
readiness remain false.

Focused native tests require pinned LOW/HIGH inputs, `AL5_LOW_DUMP`,
`AL5_HIGH_DUMP`, `AL5_LOW_BIN` and the existing Unicorn 2.1.4 dependency path:

```powershell
python -m unittest test_calibration_startup test_calibration_initializers test_calibration_marker test_boot_interface_gate test_boot_receive_isr -q
```

Validation: the combined AL5 offline suite passed **275 tests with no skips**
using the pinned native inputs and Unicorn 2.1.4. This includes 23 new test
methods for the four models, plus the extended marker checks. Source staging
passed `git diff --cached --check`. No adapter or controller was accessed.

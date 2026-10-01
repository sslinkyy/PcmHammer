# Resident command dispatcher — isolated offline reconstruction

The low editor dump's routine at `0x19C8–0x2A23` consumes a message buffer
at `0xFF8088`. It checks a type nibble of four, copies an encoded identifier
from offset two, and copies eight payload bytes from offset six. It accepts
identifier fields extracted as class `0x03` and endpoint `0xF8` or `0xF9`.
The incoming length is the low nibble of the first buffer byte.

This is a **CAN-style internal message path**, separate from the VPW dispatcher
at `0x341C`. The send helper at `0x1820` selects 11-bit versus 29-bit identifiers,
copies data into 16-byte message objects at `0xFFC010`, and manipulates their
control bytes. These observations support the CAN interpretation. The hardware
part, bit rate, physical wiring, identifier arbitration bits and live boot entry
remain unverified. The internal structure must not be mistaken for a wire frame.
For a generic comparison, the [NXP MC68336/376 TouCAN manual, section 13.4](https://www.nxp.com/docs/en/user-guide/MC68336376UM13.pdf)
documents standard/extended identifiers and eight-byte message buffers. This
comparison does **not** identify the controller's MCU or CAN peripheral: the
observed object offsets/control encoding require their own hardware evidence.

## Reconstructed internal commands

The first payload byte dispatches several commands; only the following branches
were tested. The examples in the emulator are synthetic buffer contents, not
instructions for sending packets to a vehicle.

- `0x12`: constructs operation zero and forwards payload byte one as the erase
  selector to the resident primitive. Its send-helper data is command plus the
  returned status byte. Selector validity is delegated to the primitive; these
  tests trap the call and do not validate erase behavior.
- `0x22`: consumes a BE24 address in payload bytes 1–3. In flash mode, count is
  the incoming length minus four, stored as a byte. Valid two/four-byte data
  counts and even addresses at or above `0x4000`, with final byte at most
  `0xFFFFF`, reach the resident word-program primitive. Its source is the local
  copy of payload bytes 4–7. The send-helper data contains command, echoed
  address and status.
- `0x23`: uses the same address/data/count construction and flash guards, but
  has no send-helper acknowledgment in the tested cases. Lack of a response
  therefore cannot be treated as a timeout with an automatically safe retry.

The byte at `0xFF815C` selects flash versus RAM behavior. When injected as one,
`0x22` can copy payload into synthetic RAM at `0xFF9000`; the bounds depend on
the word at `0xFF8002`. Mode initialization/transitions have not been traced.
The emulator's initial mode/pointer state is injected, not a proven session.

## Malformed input findings

The dispatcher copies all eight staged bytes irrespective of the declared
length. A synthetic length-one `0x12` input still forwards the staged second
byte as an erase selector. A synthetic length-zero `0x22` input with staged
address/data underflows the byte count to **252** and reaches the trapped
program call, sourcing bytes beyond the four-byte payload local.

These are isolated dispatcher observations with deliberately inconsistent
buffers. They do not prove that a real receive driver can deliver such inputs.
They establish that a future simulator must validate framing/length before
interpreting this layer, and that these commands must never be experimentally
probed on the only TCM.

## Emulation scope and results

`Tools/AL5/emulate_resident_dispatch.py` maps the extracted dispatcher,
synthetic stack/RAM and a return sentinel. It injects the resident function
pointer, replaces the send helper, and traps every erase/program call at
`0xFF8500` before executing a primitive instruction. No flash routine is loaded.
Execution outside the dispatcher and its two explicit stubs raises an error.
Unmapped flash destinations prevent actual writes through this harness.

Sixteen cases pass, checking primitive arguments, status data, RAM changes,
alignment/range rejection, wrong type/identifier, alternate identifier, zero
data, the unacknowledged variant and malformed lengths. Status zero/one is
injected by the primitive stub, so these are dispatcher behavior checks, not
erase/program-success evidence. `RESIDENT_DISPATCH_EMULATION.json` records
source/code hashes and per-case assertions; `RESIDENT_DISPATCH_STATIC_EVIDENCE.json`
records bounded supporting disassembly.

The dry-run planner still has zero packets and blocked readiness. Live CAN/VPW
erase/program, session entry, physical geometry, collateral preservation,
checksum compensation generation, deadlines and recovery remain unresolved.

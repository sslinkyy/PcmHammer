# AL5 reader startup contract and software quiesce

The reader now implements a local software-quiesce function and has a broader
native startup register inventory. These remain offline prototypes. Physical
VPW initialization, CPU identity, RAM ownership and safe power-cycle behavior
are unqualified. No live upload, execution, key submission or writes are enabled.

## Startup evidence and remaining contract

The pinned boot functions 0xAF0, 0xBF0 and 0xC20 execute independently in the
extended native-controls harness. It records their literal register addresses,
widths and values, including word writes at 0xFFFA00/22/24/4C-76, mixed accesses
in 0xFFFC00, and interface setup at 0xFFFD20/22/40/41. The serial-ready transition
is injected; hardware words 0, 20 and 21 exercise the native interface-selection
flag. This does not identify every register's physical semantics or prove a
complete cold-start order.

The actual 0x3B7C initialization path constructs byte 18 from ROM 0x2CFC and
byte 02 from ROM 0x2D1C, then writes them through 0x2E30 to 0xFFE800/801.
These are concrete inherited-configuration candidates. Their clock/speed meaning
is not established, so the reader does not replay these commands. Six added
cases bring the native control inventory to 16 cases. Previous terminal/flush
observations remain distinct from a qualified reset or safe exit.

## Local one-shot lifecycle implementation

The new C entry al5_ro_request_quiesce is a local function for offline caller
simulation. It has no wire opcode, adapter integration or controller invocation
path. State grows from 16 to 20 bytes; the linker/guarded RAM layout remains
nonoverlapping. The rebuilt code is 1,328 bytes at 0xFF9006-0xFF9535, SHA256
5f8ce64bf5d26a3121d6b2e941694ca95da49e15b730f708939cbb66cd1f7836.

Lifecycle states are running, software-draining and software-parked. Calling
quiesce between polling steps prevents subsequent flash reads and new reply construction.
An already pending reply can finish software submission. Observed partial RX is
discarded through its end event; idle polling alone does not end it. Busy TX or
a missing RX end keeps the function waiting with watchdog progress. Only no
software TX/RX ownership and a scripted status byte of zero permit software
park. This zero-status condition is not proof of physical transmission/drain.

Parked steps update owned counters and service the watchdog, without VPW
status/data access, TX submission or flash reads. New queued events remain
unprocessed. No reset store, resident-stack return or automatic restart is added.
The initial hardware design still requires a controlled power cycle after a
qualified quiesce; physical safety of that procedure remains to be demonstrated.
Host campaign completion alone does not invoke this local control function.

Five new compiled cases bring the runtime suite to 29 groups. They check idle
park, partial-RX waiting, busy TX plus new-request rejection, queued-RX discard
and corrupted lifecycle state. A full 1,282-request collateral/marker campaign
also exercises the local control entry through an explicit synthetic call frame
that preserves the saved assembly-loop SP/PC. That is a local caller model,
not an interrupt or a host protocol. Reader state is never presented as a
physical backup or authorization for a hardware action.

## Fresh security support audit

PcmHammer contains algorithm 50 and its AL5 probe predicts BC08 for seed 9CE5.
This is one matching captured pair, not a verified general algorithm. The
historical LOW/HIGH firmware's selector-zero handler uses fixed words at
0x3FD8/3FDA. Both the saved SPS calibration and saved PPEI calibration have
selector zero at 0x10954. The current SPS module's handler/transform/table
ranges match those in the pinned historical OS code.

Twenty native authorization cases still pass, including seed-before-key,
wrong-key/lockout and declared-length handling. Five isolated selector-one
transform samples differ from production algorithm 50; 9CE5 produces ACE1
through that native transform. Those samples do not simulate dynamic seed
generation or establish which alternate profiles are supported. The five
captured key exchanges all use the same 9CE5/BC08 pair.

AL5SavedSecuritySeed now provides strict AL5-address seed parsing. Short
67 01 37 is retained as unqualified, never interpreted as authorization. A
full seven-byte response containing seed 37xx remains a seed. Extra/truncated
bytes are rejected. Zero and FFFF seeds are observations and confer no generic
unlock authority. The read-only probe uses this parser and labels its algorithm
prediction as unverified; it still never submits a key.

The generic Protocol.Security/Vehicle.UnlockEcu route uses DeviceId.Pcm=10.
It is not an AL5 fresh-security backend. Future work must bind the current
controller/profile, target 18, seed/key state and lockout behavior explicitly.
No AL5 key sender or brute-force route is added. Fixed boot words, physical
acceptance, lockout timing and current session authorization remain separate
qualification requirements.

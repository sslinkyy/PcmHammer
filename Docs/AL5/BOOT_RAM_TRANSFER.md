# Boot RAM-transfer reconstruction — offline only

The existing low editor-memory dump contains a VPW receive dispatcher at
`0x341C` and a RAM-transfer handler at `0x3074–0x3419`. This is a boot firmware
path. Its reachability from the currently running application has not been
established. No live upload, execute, key or destructive command was sent.

## Static dispatch evidence

The receiver stores priority/destination/source/service at `0xFF8165–0xFF8168`.
The dispatcher checks destination `0x18` (with a distinct global `0xFE` path),
header flags and frame length. It branches on service `0x27`, `0x28`, `0x34`,
`0x3C`, `0x3F`, `0xA0` and `0xA1`. The `0x34` branch at `0x35FA` requires
four wire bytes, prepares response service `0x74` plus byte `0x44`, and sets
the byte at `0xFF8185` to one. This transition is now exercised in the isolated
boot dispatcher, followed by RAM transfer with retained state; see
`BOOT_SESSION.md`. Full receive hardware and application-to-boot entry remain
unproven, and no hardware upload was performed.

The `0x27` branch in this boot path prepares seed zero for subfunction one.
That differs from the live application's observed seed `0x9CE5`. Do not replace
the existing application security model with the boot handler's behavior.

The receive ISR recognizes service `0x36` at `0x3ABC` and calls the handler at
`0x3AC6`. Existing PcmHammer block framing and byte-sum helpers are useful
references, but its PCM destination and live upload path remain inappropriate
for AL5 until the session and loader requirements are proven.

## Transfer format established in emulation

The handler consumes this logical layout, excluding the VPW physical-layer CRC:

```text
priority, destination, source, 0x36,
subtype, length_BE16, address_BE24,
payload[length], checksum_BE16
```

The trailing checksum is the sum modulo `0x10000` of subtype, the two length
bytes, the three address bytes, and all payload bytes. It excludes the first
four wire bytes and the two checksum bytes. This agrees with the repository's
existing `VpwUtilities.AddBlockChecksum` algorithm; it is a packet checksum,
separate from the native calibration CRC16/compensation field.

The handler enforces an even start in `0xFF9000–0xFFA7FF` and the literal bound
`start + declared_length <= 0xFFA7FF`. In the observed implementation this means
the last written byte is at most `0xFFA7FE`. A start at `0xFF9000` permits 6,143
bytes by this bound; this is the handler's memory bound, not an established
adapter packet-size limit or a recommended block size.

For a synthetic `0x6D` request with source `0xF0` and destination `0x18`, the
responses observed from the extracted firmware are:

- subtype zero, valid copy: `6C F0 18 76 00 73`.
- invalid/odd start: `6C F0 18 76 00 74`.
- range overrun or payload-length mismatch: `6C F0 18 76 00 75`.
- bad byte-sum checksum: `6C F0 18 76 00 77`.
- subtype one: `6C F0 18 76 01 76`.

With upload-arming state clear, the handler calls its negative-response helper
with `0x22`; the helper is stubbed in these original tests. The newer boot
session harness executes that helper and records its request-byte echo and
reason in the logical send buffer; physical transmission remains untested. Subtype `0x80` attempts a call to the uploaded start address
after the end-of-frame checks. The emulator stops at that entry without
executing any uploaded bytes. No execute-capable production builder was added.

## Fault behavior relevant to future simulation

The handler copies incoming payload bytes into RAM **before** the final
payload-count, packet-checksum and arming checks. Bad checksum and unarmed
experiments therefore leave RAM modified. A declared length greater than the
actual payload can also copy a checksum byte into RAM before reporting failure.
Failure acknowledgment does not imply no memory change. This is a reason to
model the transfer as a stateful stream, not an atomic validated copy.

Address/range rejection occurs before payload copy in the tested cases. Whether
that behavior remains true under all malformed frames, interrupts or hardware
FIFO faults is not proven. Header reception, true VPW CRC, timeouts, duplicate
blocks, loss of power and session transition remain outside the emulated scope.

## Reproducible evidence

`Tools/AL5/emulate_ram_transfer.py` maps only the extracted handler, stack,
synthetic RAM/registers and four explicit hardware/helper stubs. The FIFO stub
returns a word containing a status byte and data byte; this is an abstraction
of hardware, not a transport. The upload-arming flag is deliberately injected.
Execution outside the handler/stubs is rejected, and uploaded-code execution
is trapped. Thirteen tests cover valid/empty/max-size copies, start/end bounds,
length mismatch, checksum failure, missing arming, another subtype and the
execute branch. All pass; `RAM_TRANSFER_EMULATION.json` records results and
source/handler hashes. No firmware or calibration BIN is committed.

This establishes **offline firmware behavior** for a RAM loader interface.
It does not establish flash erase scope, flash chip identity, programming
algorithm, an AL5 kernel ABI, safe live session entry or recovery. The dry-run
planner still emits zero packets and the live-write rejection remains in force.

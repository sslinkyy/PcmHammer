# AL5 remaining pending helpers and CRC/commit linkage — offline

Four cases in `PENDING_HELPERS_EMULATION.json` pass. Each runs the pending
caller through its twelve remaining helpers, using selector RAM byte
`A5+0x2DA7` set to 0 or 1 and context RAM filled with `0xA5` or `0x5A`.
External RAM starts zero. The caller stops at `0x5BAA6`, before status
restoration and its epilogue. This is not a complete application startup.

## Remaining helper sequence

The real helpers run in caller order:

1. `0x55298`: builds calibration/flag-dependent bytes around `A5+0x82C`,
   `+0x82E`, `+0x832` and `+0x8AA`; calls real mask helper `0x97218` and the
   bit-count clear helper `0xA9D8C`.
2. `0xBAED4`: clears or initializes fields at `A5+0x83C–0x869`, including
   values from calibration `0x15A80` onward and indexed tables near `0x15E00`.
3. `0x67BC8`: uses real byte-copy helper `0xC3B80` to initialize four
   twelve-byte records from ROM `0x67D46` at `A5+0x7CC` with twelve-byte stride.
4. `0x590A0`: copies four calibration words into `A5+0x7C4–0x7CA`.
5. `0x5D894`: uses real word-setting helper `0xC3B6C` around `A5+0x808`.
6. `0xC4538`: initializes ten bytes at `A5+0x870–0x879` from calibration
   `0x0D76C–0x0D775`, closing the earlier ten-byte gap.
7. `0x60AE8`: clears three bytes at `A5+0xB25–0xB27`.
8. `0x90E48`: writes two `0xFF` bytes in each of five records beginning at
   `A5+0x958`, with 37-byte stride.
9. `0xA44D0`: writes `0xFF` to `A5+0xA8E/+0xA8F`.
10. `0xA4228`: sets or clears only bit 2 of 91 bytes at `A5+0xA30`, based on
    the low two bits of calibration bytes beginning at `0x10AA8`.
11. `0xC5938`: returns without context writes in this extracted helper.
12. `0x622F4`: clears four words at `A5+0x798–0x79E`.

These are address/operation observations, not established parameter identities.
The byte-copy and word-setting helpers differ from the bit-count memory helper;
their argument units must not be interchanged.

## Coverage is not complete initialization

Combined with the earlier defaults, the caller writes 2137 of 2546 context
bytes, leaving 409 untouched. Comparing the two sentinel runs reveals 500
different bytes: the 409 untouched bytes plus 91 written bytes retaining bits
other than bit 2. Write coverage therefore overstates how many bytes are fully
rebuilt. The results agree for the two tested selector values, but do not prove
every selector or external-RAM state.

The stored CRC at `0xFF8B30–0xFF8B31` remains untouched through these helpers.
Neither a persistent-storage commit nor CRC generation occurs in the tested
pending caller sequence before `0x5BAA6`.

## Separate preparation and synthetic persistence

After the initialization snapshot, the harness explicitly invokes the already
traced preparation routine `0x5BAB8`. This is a separate boot-preparation call,
not evidence that pending startup invokes it automatically. Ten subsystem calls
are bypassed, with their unknown effects omitted. Real CRC routine `0xA95D0`
computes the CRC over the 2544 payload bytes and preparation stores it at
`0xFF8B30`. Execution stops at storage entry `0x226F0`, whose source argument is
`0xFF8140`.

The prepared context is then supplied to the existing atomic host storage model
with a pending first-bank record. The real update caller's seven modeled
operations commit it to bank `0x6000`, clear the first-bank marker, and the real
selector reselects record `0x6028` with an identical context hash. Flash
implementations do not execute.

All four prepared contexts have matching CRCs and modeled commits. However,
the prepared contexts still differ between sentinel fills. A correct context
CRC cannot establish that the payload was initialized correctly, and the
modeled commit cannot establish physical recovery or preservation.

## Evidence and next work

`PENDING_HELPERS_STATIC_EVIDENCE.json` contains the new bounded helper/dependency
disassembly with source hashes; earlier caller/default and preparation code is
preserved in the existing static evidence files. No raw calibration or context
contents are exported. Reproduce with `Tools/AL5/emulate_pending_helpers.py
--low ... --high ... --output ...` in the existing WSL Unicorn environment.

The dry-run report hash-links this evidence while keeping complete context
initialization, physical persistence and recovery false. No packets are emitted
and the working Mode 0x23 reader is unchanged.

The subsequent `STARTUP_CONTEXT.md` executes the real cold RAM clear and links
the startup/context invocation statically. Bounded cold contexts now converge
between fills, while intervening startup and preamble effects remain omitted.
Next trace those effects and distinguish the other invocation path before
treating context reconstruction as complete. Physical erase geometry,
programming transport and hardware recovery remain separate unresolved work.
No live destructive command or experimental service is enabled or performed.

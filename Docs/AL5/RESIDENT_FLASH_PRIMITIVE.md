# Resident boot flash primitive — static evidence only

The saved low editor dump contains a routine at `0x2A58–0x2C8F`, copied by
`0x2C90` to `0xFF8500` (0x238 bytes). Initialization at `0x13D0` installs that
RAM address in `0xFF814C`; the routine at `0x19C8` checks/reinstalls it. Indirect
calls through that pointer appear at `0x1B64`, `0x1F34` and `0x21F4`.
The caller now has isolated dispatcher evidence; see `RESIDENT_COMMAND_DISPATCH.md`.
These are internal code/ABI observations, not live diagnostic packet definitions.
No flash primitive has been executed, including in an emulator.

`RESIDENT_FLASH_STATIC_EVIDENCE.json` records bounded disassembly and source
hashes. `resident_flash_inventory.py` verifies the selector dispatch bytes and
extracts the table/starts into `RESIDENT_FLASH_INVENTORY.json`. It is file-only
and always reports blocked readiness with zero packets.

## Internal operation and arguments

Relative to the argument base at `8(A6)`, a longword operation of zero selects
the erase branch; one selects word programming. Other values return one.
Erase reads a selector byte at argument offset 4. The selector upper bound is
`0x12`; selector zero branches to rejection. The table contains 19 BE16
relative offsets. The raw indexed extension at `0x2A82` is `0x0206`: it uses
`D0.W * 2`. Capstone's text omits that scale; reading it as an unscaled byte
offset would reconstruct the table incorrectly.

Selectors 1–18 load these starts, in order:

```text
04000 06000 08000 10000 20000 30000 40000 50000 60000
70000 80000 90000 A0000 B0000 C0000 D0000 E0000 F0000
```

The erase branch at `0x2B3E` changes a hardware register, performs flash
unlock/erase command writes, and polls the selected address while feeding the
watchdog. Its final low-byte comparison is against `0xFF`, returning zero on
that comparison's success and one otherwise. There is no software deadline in
this bounded loop. Hardware state, bus width, flash part identity, complete
erase extent and recovery behavior remain unverified.

The program branch reads a byte count at argument offset 5, a source pointer
at offset 6 and a destination pointer at offset 10. It performs command writes,
copies a word, polls status, compares the destination/source word and advances
both pointers and the completed count by two. On the observed failure path it
issues a reset command and returns a nonzero byte. On the observed success path
it clears that byte. No alignment/range guards are visible in this primitive.
The one-byte count is an internal ABI limit, not a transport block-size proof.
An odd count can include one extra byte because the loop advances in words.
A zero count bypasses initialization of the returned local status byte; callers
must not treat it as a deterministic success case.

## Implications for offline planning

The calibration spans `0x8000–0x15FD7`. If adjacent selector starts correspond
to sector boundaries, it occupies selectors 3 and 4, covering candidate erase
intervals `0x8000–0xFFFF` and `0x10000–0x1FFFF`. Together these inferred intervals
contain **41,000 bytes outside the calibration**, at `0x15FD8–0x1FFFF`.
This is a preservation hazard inferred from starts; it is not proven physical
geometry. A calibration-only backup would be insufficient for that hypothetical
erase plan. Do not substitute these intervals for confirmed erase geometry or
enable a writer based on this evidence.

Next trace the internal callers' argument construction and their incoming
buffer sources, then identify the actual flash hardware and validate geometry
against independent existing evidence. Session/security, wire commands,
acknowledgments, deadlines, interrupted-operation recovery and post-write
verification remain required. The current direct reader and hard write block
are unchanged.

# Short receive frames and stale dispatch bytes

[Eight bounded cases](LOADER_STALE_BUFFER_EMULATION.json) combine synthetic
completion flags with actual saved receive and dispatch instructions. The report
links the captured loader, static instruction inventory and both emulator scripts
by hash. No flash, finalize, block or reset handler executes: each route stops
at its entry or the shared exit boundary. No adapter or controller is contacted.

## Stale-byte routes

The receive loop starts writing at `0xFFFF9AA0` for each frame. It does not
clear the rest of the buffer before dispatch. A synthetic two-byte frame writes
only priority and destination. With fresh zero-filled RAM it returns to receive;
with an older `F0 36 EE` tail in RAM it reaches the Mode `0x36` erase route.
Three- and four-byte variants also reach that route when the missing subtype
is stale. Replacing the stale subtype with `FF` or `00` reaches the finalize or
block-parser route. A stale `F0 3C 55` tail reaches the shared exit path.

A first frame rejected on completion flag `0x40` still writes its five data
bytes to the buffer. A later two-byte frame with synthetic zero completion
flags can reuse its tail and reach the erase-route trap. This establishes a
software stale-buffer path under the modeled input. It does **not** establish
that the physical FIFO accepts such a short frame or reports it as valid.
No corresponding destructive request is established by the saved trace census.

Host validation must require an independently supported minimum frame length
and complete header before dispatch. A future transport must not rely on
receive-buffer initialization or assume rejected frames leave no state.

## Address boundary

The saved loader is 1,590 bytes at `0xFF9000`; the receive pointer is
`0xFFFF9AA0`; the initial stack is `0xFFA7FE`. If those addresses alias by their
low 24 bits, the receive pointer would be 3,422 bytes below the initial stack.
The actual stack descends during calls, and any aliasing, RAM decode, controller
buffer limit and safe receive capacity remain unverified. The current emulator
maps `0xFF8000` and `0xFFFF0000` separately; its 16-byte write trap is only an
experiment limit. This arithmetic must not become a physical buffer bound.

The existing project artifacts inspected here contain saved firmware, traces
and generic boot-register observations, but no identified part number or
independent register contract for the FIFO at `$E800.w`/`$E801.w`. The loader
proves how it uses those addresses; it does not identify the external hardware
or CRC behavior. The planner records physical short-frame acceptance, RAM
capacity and address aliasing as unverified.

## Reproduction and next work

Run `Tools/AL5/emulate_loader_stale.py --loader <private-captured-loader>
--output <report>` in the existing WSL Unicorn environment. The script exports
only metadata and observations. Physical framing, chip-select mapping,
collateral preservation and demonstrated recovery remain open before a live
writer can be considered. The working Mode `0x23` reader and AL5 write rejection
are unchanged.

# Receive-loop boundaries and priority-dependent budget

[Eleven bounded cases](LOADER_RECEIVE_EMULATION.json) execute saved receive-loop
instructions with synthetic register events. MMIO reads are intercepted before
execution; the host writes modeled bytes to emulator RAM. Watchdog and short
delay helpers use return stubs. Dispatch and shared exit paths are trapped.
No adapter, controller or live commands are involved. Source/generator hashes
make the report reproducible from the existing private loader.

## Software register interpretation

At `0xFF9056`/`0xFF907C`, the code shifts the byte at absolute-short `$E800.w`
right by five. Zero continues polling; seven on initial acquisition discards a
byte via `$E801.w`. The first nonzero, nonseven event stores the first byte.
Subsequent nonzero events store bytes; values below five continue accumulation,
while five or above proceed to completion metadata. These short operands map
to `0xFFFFE800`/`0xFFFFE801` in the emulator.

The completion path reads another data byte and rejects it if either `0xC0` or
`0x30` mask is nonzero. Synthetic `0x40` and `0x10` flags both return to receive
without decrementing the budget or reaching dispatch. Their physical meanings
(including any CRC/framing error interpretation) remain unverified. These are
firmware observations, not an identified controller datasheet contract.

## Length, timeouts and frame budget

- Two-byte synthetic input reaches the dispatcher boundary with no prior
  minimum-frame-length check. The dispatcher is trapped before parsing it;
  this does not show that an undersized service request is accepted.
- A 17-byte stream reaches the explicit 16-byte model write limit. No intervening
  firmware length guard is observed. **Sixteen bytes is only a test boundary**,
  not the controller's physical buffer capacity or proof of actual corruption.
  Future host validation must impose proven lengths and receive bounds.
- Both initial-idle and partial-frame counters compare against `0x50000` and
  branch to the shared exit at `0xFF9236`. Tests seed the counters near that
  compare, so they establish branch behavior only, not elapsed time or full
  polling endurance. The preceding sender report traps the shared reset path.
- Completion decrements byte `0xFFFF9A72`, exiting when it becomes zero before
  entering dispatch. A one-frame budget therefore exits before dispatch.
- Repeated priority `0x6C` frames exhaust an initial budget of 255: 254 reach the
  dispatcher priority prefix, and the 255th reaches exit. Repeated `0x6D` frames
  execute the saved prefix's store of `0xFF` back to the budget; all 256 supplied
  frames reach that prefix and the budget remains 255. The rest of dispatch is
  replaced with return to receive in these cases. Do not infer a universal
  255-frame session limit from the decrement alone.

## Reproduction and next work

Run `Tools/AL5/emulate_loader_receive.py --loader <private-captured-loader>
--output <report>` in the existing WSL Unicorn environment. Metadata, counts and
hashes are exported; raw loader bytes and complete packets are not.

The planner hash-links the report while keeping physical FIFO and timeout
verification false, readiness false, erase scope null and packet lists empty.
The working direct reader and unconditional C# write rejection are unchanged.

Next identify the actual FIFO controller and register/error-bit contract from
independent hardware or saved firmware evidence. Connect receive and sender
observations to a complete session capture if one already exists. Explicitly
bound the actual RAM receive region and stale-buffer behavior before any future
host transaction model. Physical programming, collateral preservation and
demonstrated recovery remain unresolved.

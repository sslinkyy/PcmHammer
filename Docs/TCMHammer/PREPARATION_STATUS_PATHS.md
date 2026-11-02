# Native preparation status and pending-frame paths

`Tools/AL5/emulate_preparation_statuses.py` continues the source-pinned application request/preparation trace against the historical persistent banks. No adapter or physical controller is opened. Native flash implementations are intercepted before their first instruction; host memory changes model atomic effects, not physical NOR behavior or recovery.

## Examined paths

The successful atomic model executes the real storage caller and native copy/program wrappers. It performs thirteen host-modeled effects: one erase, seven tail-copy chunks and five program calls. All seven storage wrapper frames return. The prepared context digest matches the new bank context; the old/new record markers become 0000/FFAA. Application preparation then reaches BFC1 and the accepted park. Subsystem stubs, atomic operations and physical reset remain assumptions.

An erase-error case writes the synthetic error word 2000 and leaves both bank contents unchanged. The caller still reaches copy-wrapper entry 22CF0. The model stops there; it does not silently invent a failed erase's partial contents or continue as if success were established.

For both copy and program, separate cases distinguish:

- Correct modeled payload bytes accompanied by an error status.
- A deliberately changed payload accompanied by a zero status, causing the native readback comparison to detect the mismatch.

Copy failures reach 22DBC; program failures reach 22CC2. Both set marker 6124, mask interrupts and retain the failing wrapper frame. No later BFC1 park is reached. The earlier erase wrapper returns; in program-failure cases, the copy wrapper also returns. Observed return PC and SP equality bind each return to its original call frame. Remaining frames are never classified as reusable.

An omitted write is not automatically a mismatch: the historical tail is FF, and an erased destination may already match it. The mismatch cases therefore change actual modeled bytes and record expected/written payload digests. This establishes native comparison behavior without pretending that every omitted write is detectable.

## Limits and relationship to reset

Successful atomic erase/programming, modeled error statuses and modeled mismatch contents do not establish actual flash effects. There is no partial erase, partial-word programming, electrical timing, interrupt delivery or physical reset model. Native program/copy loops are exercised; their copied flash implementation bodies never execute.

`emulate_application_reset_chain.py` separately shows that a synthetic status-20 reset carrying marker 6124 can reach boot handling. These paths do not prove that the physical controller will reset, retain the marker, accept a fresh session or recover after damaged persistent storage. Reset remains explicitly injected.

## Reproduction

With task-local Capstone/Unicorn dependencies on PYTHONPATH:

- `test_preparation_statuses.py --low LOW --high HIGH` checks all six scenarios, native endpoints, distinct status/readback effects, wrapper-frame returns, context commit and disabled authority flags.
- `emulate_preparation_statuses.py --low LOW --high HIGH --output NEW_JSON` retains source hashes, exact case assumptions, effect hashes, wrapper-frame observations and bank difference counts. Both source images are pinned by size and SHA-256.

Detailed reports remain local/private. Live upload, execution, writes, automatic session reuse and recovery authorization remain unavailable.

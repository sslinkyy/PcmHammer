# Conditional FIFO comparison and unresolved completion ordering

The [saved comparison](FIFO_CANDIDATE_COMPARISON.json) pins the existing startup
and loader evidence, checks specific saved instructions, and runs three bounded
receive scenarios in the existing offline emulator. MMIO is intercepted;
dispatch/exit are trapped. No adapter or controller is opened.

## Manufacturer comparison

The [Motorola MC68HC58 datasheet](https://datasheet4u.com/pdf-down/M/C/6/MC68HC58_Motorola.pdf),
sections 5.1, 5.3 and 5.4, matches the loader's first/middle/last transmit controls
`14/04/0C`, busy mask `03` and completion masks `C0/30`. Under this candidate,
exit control `40` sends BREAK; the separate `D0C2` store remains an unidentified
reset mechanism. RFS values 5–7 indicate completion at the FIFO head, and
parallel data reads consume bytes. Status freezes while chip select is asserted.

The [MC68336/376 register summary](https://www.nxp.com/docs/en/user-guide/MC68336376UMD.pdf),
D.2.19/D.2.21, conditionally decodes saved startup stores `FFE8` at `FFFA54`
and `D820` at `FFFA56` as a 2 KiB window starting `FFE800`, with synchronous
mode, upper-byte selection, read/write access and supervisor space. This is a
register-map comparison, not identification of the fitted MCU or board wiring.
The synchronous setting does not establish separate chip-select edges for the
loader's byte reads.

## What the saved code and experiments establish

Saved loader instructions read status at `FF907C`, store data into `(A0)+` at
`FF9086`, and only then compare the shifted status with five. The completion
path reads status again at `FF9092` and data into D3 at `FF9096` before testing
the flag masks. This read order is directly supported by existing disassembly.

The previous synthetic model marks the last payload byte with status five and
supplies a separate following flags byte. Its control case still reaches the
dispatcher trap. It was never a manufacturer FIFO implementation.

With an isolated literal candidate sequence, all five payload bytes have status
two, then the completion byte has status seven. The saved code stores six bytes
and requests another data read: the bounded model reports exhaustion rather
than inventing a valid empty-FIFO byte. With another frame queued, completion
has status six; its byte is stored and the next frame's first byte is consumed
as flags, rejecting the modeled frame before dispatch. These are hypothetical
software outcomes, not observations of physical FIFO timing or a proven defect.

Chip-select timing, bus width, status latching, byte-lane mapping and address
aliasing could change the physical interpretation. Neither a matching transmit
table nor these literal scenarios resolves them. The MCU/FIFO identities and
receive contract stay unverified. Existing receive, stale-buffer and sender
reports remain bounded software evidence, not hardware qualification.

## Reproduction and remaining dependencies

Run `Tools/AL5/audit_fifo_candidate.py --loader <private-captured-loader>
--output <report>` in the existing WSL Unicorn environment. The report exports
only metadata and hashes. The file planner hash-links it while keeping all live
gates closed, erase scope null and packet lists empty. C# behavior is unchanged.

Further protocol qualification requires independent hardware identification or
an already recorded complete exchange that resolves receive/acknowledgment
semantics. The existing five write traces lack that exchange. Physical geometry,
current collateral/bank backups and demonstrated recovery are also unresolved;
old saved images cannot establish their current condition. A compatible spare
and proven recovery remain prerequisites for a destructive bench stage. Do not
generate a new flash capture on the user's only installed TCM.

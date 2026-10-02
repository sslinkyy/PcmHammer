# Hash binding and conditional artifact coverage

`Tools/AL5/preservation_manifest.py` binds caller-supplied baseline and candidate
calibration files to explicit expected hashes. It runs the existing minimal-test
allowlist, identity and checksum checks, then inventories optional collateral and
persistent-bank files. Output contains hashes, lengths and gaps, not BIN bytes,
packet construction or hardware access. CLI exit is always 2 (blocked).

The conditional artifact set comprises the 57,304-byte baseline and candidate,
41,000 collateral bytes at `0x15FD8–0x1FFFF`, and the 16,384-byte region containing
persistent banks at `0x4000–0x7FFF`. The collateral range derives from the saved
loader and conditional AMD sector evidence; the bank region derives from the
separate application preparation analysis. They do not establish physical chip
mapping or an executable erase scope.

Each supplied component requires its expected SHA256 and exact length. Hash
mismatches, wrong lengths, malformed hashes and incomplete byte/hash pairs are
errors. Omitted collateral/bank pairs are explicitly missing. All required file
bindings may pass while current physical provenance, preservation and recovery
remain false. The source of a saved file cannot become a current controller
backup merely because its hash matches.

The finalization marker at `0x1FFFE` is inside collateral and may be rewritten.
Its expected before/after handling remains unresolved. Application preparation
may separately modify persistent banks. Neither region can be silently declared
preserved or omitted from a future backup/readback strategy.

## Use

Run `Tools/AL5/preservation_manifest.py --current <baseline> --candidate <candidate>
--expected-current-sha256 <pinned-hash> --expected-candidate-sha256 <pinned-hash>
--output <private-report>`. Optional `--collateral` and `--persistent-banks` paths
require `--expected-collateral-sha256` and `--expected-persistent-banks-sha256`
respectively. Output cannot overwrite any input artifact. Keep private BINs and
derived physical-backup material outside Git or under ignored `LocalOnly`.

Tests cover calibration-only gaps, complete synthetic coverage with all physical
gates closed, candidate changes, incorrect collateral length and incomplete or
malformed hash pairs. The planner hashes the implementation and keeps readiness
false, erase scope null and all packet lists empty.

Next obtain independent mapping, provenance and permitted-change evidence for
the affected regions before specifying restoration or final readback behavior.
An already recorded complete programming exchange and demonstrated recovery
remain required before any live AL5 writer can be justified.

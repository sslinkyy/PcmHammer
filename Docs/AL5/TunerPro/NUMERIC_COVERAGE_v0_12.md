# AL5 complete numeric stock coverage, v0.12

The completed v9 report confirms all eight previously missing D5000/D5005
Pattern E-H vectors with 24 isolated markers: rows 0, 8 and 16 per column.
Every marker read back 200 km/h and restored the original raw bytes. The
secondary object closed without saving; GUI data remained unchanged. No vehicle
I/O or checksum finalization occurred. The original private report hash is in
the redacted `REMAINING_COLUMN_EVIDENCE_v9.json`; local CTZ paths are removed.

D5000 E/F/G/H start at 0x11BC8 / 0x11C10 / 0x11C58 / 0x11CA0.
D5005 E/F/G/H start at 0x11BEC / 0x11C34 / 0x11C7C / 0x11CC4.
Each has the 0011 count header and 17 contiguous unsigned BE16 cells scaled
by 1/128. Complete stock vectors match native export values within 0.001.
Marker changes may affect only one byte; the field width is verified from full
word decoding and vector structure, rather than changed-byte count.

XDF v0.12 appends eight tables to v0.11 and preserves every existing address,
width and equation. Its audit passes 291 numeric entries across 298 items:
127/127 native IDs represented and 2517/2517 unique numeric cells compared,
with no missing numeric coordinates or audit errors. The four native text
cells are tracked through their separate enum evidence, outside this numeric
count. Reference BINs and the proprietary export remain outside Git.

Full numeric stock decoding does not establish marker proof of every cell,
all pattern runtime selection, edited calibration acceptance, or TunerPro GUI
validation. New E-H GUI checks remain pending. Existing stock/PPEI scalar and
stock D5073 checks are retained. Native checksum reproduction remains verified
against stock, PPEI and three independently editor-finalized edited payloads.

The next development stage is offline programming protocol and preservation
work: establish the diagnostic session/loader path, exact flash geometry,
collateral preservation and recovery. Use WRITE_PROTOCOL.md and the existing
boot transfer/resident dispatcher evidence; do not redo completed mapping.
The dry-run plan still emits zero packets and blocks readiness. AL5 live writes
remain blocked. No live erase/program or experimental upload was performed.

Validation: 52 offline tests pass, including rejection of unrestored markers,
wrong contexts/coordinates, vehicle-I/O flags and an unsampled-cell mismatch.
No C# source or direct-reader behavior changed in this milestone.

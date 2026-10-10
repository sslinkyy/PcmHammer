# Truck AL5 physical hardware evidence

Recorded 2026-10-10 from five original photographs supplied by the owner, who
states that they show the TCM removed from their truck. Photograph filenames
are dated 2026-10-08. These are original photos, not the earlier AI-expanded
presentation image. Originals remain in local attachments; serial numbers and
photographs are not added to Git.

## Observations

- The exterior GM label reads end-model P/N `15183963`, broadcast code `3963`,
  and service number `15768288`.
- The other exterior label reads ECU-TCM 12 VOLTS, base/model `29537441`, and
  date `01-16-2003`. This ties the physical unit to the owner's earlier reported
  hardware number. It does not independently read the installed OS/calibration.
- The rectangular memory IC has an AMD logo and readable `AM29F800BB` family
  marking in the two closeups. The suffix appears to be `-70SI`, but glare,
  coating and viewing angle make that suffix provisional. Confirm the complete
  marking before selecting a replacement or programmer profile.
- The package appears consistent with the manufacturer's 44-pin SO option.
  The large adjacent square IC's marking is not readable; processor model,
  peripheral identification and debug-pad assignments remain unknown.

## Relationship to offline evidence

The [Am29F800B manufacturer datasheet](https://www.batronix.com/files/Datenblaetter/29__/AM29F800B.pdf)
specifies 8 Mbit / 1,048,576 bytes, 5 V operation, and a bottom-boot `BB` variant.
Its manufacturer/device IDs match the captured loader's `0x0001` / `0x2258`
constants. See [captured loader dispatch](CAPTURED_LOADER_DISPATCH.md).
No autoselect command was sent to this module: this is photographic identity,
not an electrically read device ID.

This advances the fitted flash family from a software-derived candidate to
owner-attributed physical evidence. It establishes that the photographed flash
is AMD, not Intel AB28F400B5. The owner's loose Intel chips are not substitutes.
It does not prove CPU address mapping, active bus width, protection state,
loader execution safety or successful recovery.

The [geometry report](LOADER_GEOMETRY_FINALIZATION.md) remains conditional on
CPU mapping. Its 41,000 collateral bytes and separate persistent-bank risks
are not resolved by a chip photograph. No executable erase scope or planner
readiness flag is changed.

## Next evidence

The owner reports a T48 with ADP_S44_EX-1 and Xgpro support for Am29F800BB.
Equipment support is not a validated chip-level recovery procedure. A future
full-chip backup must have repeated matching reads, a retained original dump,
and verified byte order against known calibration anchors. A matched replacement
must be independently verified; original-chip preservation and rework are
separate physical tasks. No chip removal, erase, program, loader upload or live
service was performed for this note.

## Original-photo provenance

Local attachment filenames and SHA256 digests:

- `1-20261008_184132.jpg`: `49c87925e74f3a21768471848b413ce6ad0ab843fea9eeae87feda2c8f5f17e9`
- `2-20261008_184026.jpg`: `c462b0cf1f8bb436b93c517fe7bd85cb221474d664b2a33fe4be5129dd3cf19b`
- `3-20261008_183923.jpg`: `448a8d30e67fe74f6707f897c33e85e52cfa27666341662d124e11df6d75381e`
- `4-20261008_183324.jpg`: `f22704a6a0dc010bd6d18898ee6a64ac2b9b35acd7c861b36cdf46c9feca5364`
- `5-20261008_181842.jpg`: `c6399d2104ea0a881fc6d94185d28733e35be9be68f13e586311c4e1b4686138`

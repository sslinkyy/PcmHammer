# AL5 direct read status — OS 15184109 / calibration 15183960

## Live-read breakthrough

The AL5 at VPW module `0x18` responds to stock-firmware Mode `0x23` memory reads at normal VPW 1X speed without requiring a security-key exchange or RAM kernel.

Validated live requests:

- `0x08024` returned `00 E7 B0 58` = transmission calibration ID 15183960.
- `0x0A996` returned `11 F7 0C 68 ...`, matching the known reverse/1st gear signature.
- `0x158A8` returned `00 11 00 09`, confirming 24-bit addressing above 0xFFFF and the known D5196 17x9 header.

The direct reader successfully captured `0x08000-0x15FD7` (57,304 bytes), validated known anchors, and validated the existing BE16 word-sum invariant.

## Current PPEI calibration read

Live direct-read SHA-256:

`d0bcce91cea041bcf82317c73708c2289c78064aa542d6a63c12d3d6d78adc3f`

Comparison against the verified stock/Test-1 raw calibration segment found:

- 102 changed bytes
- 31 contiguous raw diff ranges
- stock and PPEI calibration segments both sum to `0x0000` as BE16 words

### Confirmed / strongly decoded PPEI changes

#### D5025-D5028 — WOT upshift RPM

PPEI sets every High/Low cell in Patterns A-D to 3450 RPM.

| Table | Stock A | Stock B | Stock C | Stock D | PPEI |
|---|---:|---:|---:|---:|---:|
| D5025 1->2 | 3200 | 3200 | 2900 | 3200 | 3450 |
| D5026 2->3 | 3200 | 3200 | 3000 | 3200 | 3450 |
| D5027 3->4 | 3250 | 3250 | 3100 | 3200 | 3450 |
| D5028 4->5 | 3260 | 3260 | 3200 | 3275 | 3450 |

The raw PPEI value is `0x6BD0`; the RPM encoding is raw/8.

#### D5196 — Torque Limits

Only the 3400- and 3600-RPM rows change. PPEI copies the stock 3250-RPM row into both.

TPS columns: 0, 20, 40, 50, 60, 70, 80, 90, 100%.

- Stock 3400: `-161,-161,-119,-76,-55,-35,5,45,45`
- PPEI 3400:  `-156,-156,-59,16,51,136,281,403,626`
- Stock 3600: `-161,-161,-161,-161,-161,-161,-161,-161,-161`
- PPEI 3600:  `-156,-156,-59,16,51,136,281,403,626`

This is a large removal of the stock high-RPM torque-limit taper near the new 3450-RPM WOT shift point.

#### TCC slip inhibit

Strong static mapping from unique stock raw values and adjacency:

- D5231: 600 RPM -> 2000 RPM at `0x145BE`
- D5233: Enable -> Disable at `0x145C0`

#### Unmapped patch

- `0x10A24`: `00 -> 40`
- This sits in a code-like region containing repeated `4E71` words.
- Do not assign a calibration ID until marker-differential mapping or disassembly proves it.

#### Checksum field

- `0x15FD4-0x15FD7` changed from `4E 35 D0 40` to `DA E2 BB 2E`.
- The resulting PPEI segment still satisfies the BE16 zero-sum invariant.

### Important unchanged controls

The direct raw comparison shows no changes at the marker-verified addresses for:

- D5048-D5051 TAP presets
- D5120-D5127 TAV presets
- D5130-D5137 off-going pressure
- D5080-D5095 base desired shift times
- D5194 maximum torque reduction request
- D5195 minimum torque reduction request
- D1201-D1205 / D1220 gear ratios

## Diagnostic significance

The PPEI calibration raises WOT shift RPM to 3450 and removes much of the stock D5196 high-RPM torque limiting, while leaving the verified clutch pressure / volume / base shift-time controls stock.

That combination is a strong calibration-level candidate for the observed pre-shift flare: the TCM is commanded to shift later under substantially more permitted torque without corresponding clutch-handoff pressure/volume/timing changes. It should be treated as a strong mechanism hypothesis, not yet as proof of the sole cause.

## Current development path

1. Keep the AL5 direct-read path strictly read-only.
2. Preserve the 57,304-byte live calibration segment as a reference.
3. Map the remaining `0x10A24` patch.
4. Build the corrected first test calibration from verified stock rather than layering changes onto PPEI.
5. Prioritize the 1->2 clutch handoff while retaining torque-management authority.

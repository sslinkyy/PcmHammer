# Dual-adapter bench battery, 2026-10-22

The GT does receive in LISTEN ONLY mode when an exact source or destination
filter is enabled. Earlier zero-frame tests used a configuration that did not
admit traffic on this GT. They did not demonstrate absence of monitor support.
The available software/bench battery was run with no flash, loader, security
access, controller reset or ECM speed-negotiation commands.

## Setup and scope

The user confirmed the bench ECM, powered supply and OBDX Pro GT / OBDLink SX
connected through a Y splitter. USB ports remained COM9 / COM8 respectively;
no physical cable or power changes were requested. This was a short-frame,
paced, read-only diagnostic test. It is not a controller-writing qualification.

`DUAL_ADAPTER_BATTERY_20261022.json` records 33 matrix cases: 31 completed and
two blocked before their diagnostic requests because mask readback did not
match the requested setting. Completing a case means it executed and cleaned
up, not that reception passed. Its 159 SX queries all received the expected
ECM PID-support reply. A separate public capture-path check also received its
expected reply. Frame CRCs were independently derived offline for 103 GT
network records, with zero mismatches.

## GT receive findings

- All-filters-off captured zero frames, in LISTEN ONLY and ON-mode controls.
- Exact FROM `10` admitted ECM replies and broadcasts. FROM `F1` admitted SX
  requests. Turning these filters OFF stopped reception; unrelated FROM `55`
  admitted no observed traffic.
- Exact TO `6A` admitted functional requests; TO `6B` admitted replies. Earlier
  TO `F1` did not match these functional OBD-II reply headers.
- The tested FROM and TO range filters admitted no frames, including narrowed
  ranges encompassing the observed addresses. Their effective behavior remains
  unresolved; do not treat successful readback as receive qualification.
- Combining FROM `10` with TO `6A` admitted no observed frames. Combining FROM
  `10` with compatible TO `6B` admitted all 25 repeated ECM replies. This is
  consistent with intersection of enabled exact filters in the tested cases.
- Timestamped exact-source captures worked. The CRC-validation-OFF case also
  captured valid replies. Neither test qualifies malformed-frame handling.
- Priority-mask `080000` / `400000` ON settings echoed ON but GET reported OFF.
  Both cases stopped before diagnostic requests and restored settings.

The repeated FROM `10` case captured 25/25 replies plus four broadcasts. The
FROM `F1` case captured 25/25 requests. The compatible combined-filter case with
timestamps captured 25/25 replies. These are separate directional runs, not a
single complete two-direction capture. The traffic consists of identical
requests/replies, so matching counts alone cannot exclude an offsetting loss
and duplicate.

The production capture tool now accepts `--source-id BYTE` (e.g. `0x10`) and
verifies/restores that exact filter. An actual bench run through this path
captured the ECM reply and broadcasts, with successful cleanup. No adapter
vehicle-send command was added to the capture client. The receive scope is
recorded as `exact_source`; the unfiltered configuration is explicitly labeled
`unqualified_all_filters_off`. This option does not claim both directions.

## SX and configured 4x source findings

With GT configured at 1x, SX monitored 100 acknowledged GT requests and all
100 corresponding ECM replies, plus 19 broadcasts, without a reported monitor
overflow or premature exit. The source loop was deliberately paced; this
does not establish a maximum frame rate or flash-size throughput.

With GT read back at 4x, three fixed requests were acknowledged by GT. SX
decoded none of those requests and no PID replies, but decoded two ECM
broadcasts. ECM remained at 1x. An immediate 1x control captured all three
requests and replies plus two broadcasts. The physical 4x waveform was not
independently measured; this does not prove an absolute SX hardware limit.

All SX monitor exits returned a prompt. The final GT inspection confirmed
network OFF **before** inspection cleanup and again afterward, protocol VPW,
speed 1x, timestamps OFF, CRC validation ON, CRC display OFF and original
filter settings. SX volatile settings remain headers ON, IFR OFF, and the
functional OBD-II transmit header `686AF1`; no persistent save was used.

## Reproduction

These commands require the same confirmed isolated bench, idle adapters and
explicitly verified current ports/API. Never run concurrently with a writer.
Output files must be new. Run from the repository root:

```powershell
python Tools/AL5/bench_adapter_battery.py --gt-port COM9 --sx-port COM8 --bench-ecm-confirmed --output LocalOnly/AL5/new_matrix.jsonl
# Matrix subsets: --extended-only, --routing-only, --combined-only, --repeat-only
# --repeat-only --repetitions 25 repeats three verified exact-filter profiles.
python Tools/AL5/bench_dual_adapter_probe.py --gt-port COM9 --sx-port COM8 --bench-ecm-confirmed --listener sx --count 100 --output LocalOnly/AL5/new_sx_repeats.jsonl
python Tools/AL5/bench_dual_adapter_probe.py --gt-port COM9 --sx-port COM8 --bench-ecm-confirmed --listener gt --gt-source-id 0x10 --output LocalOnly/AL5/new_gt_filtered.jsonl
```

The new matrix permits only the existing SX PID-support query; GT ON controls
permit no GT vehicle request. The separate SX-monitor test permits only the
fixed GT PID-support frame, with count limits 100 at 1x or three at configured
4x. Unknown payloads, programming services and bare CR are rejected. Partial
responses are retained, and no failed request is automatically retried.
77 offline tests passed for these tools and the existing capture, speed,
inspection and monitor guards. They do not replace the hardware observations.
Raw logs stay under ignored `LocalOnly/AL5`; the JSON report pins their hashes.

## What remains untested

Electrical silence, loading, IFR suppression on the wire, USB/power disconnect
behavior, independent physical bit-rate confirmation, GT 4x reception, ECM
4x transitions/return, continuous two-direction capture, arbitrary/long VPW
frames, deliberate malformed signals, saturation/overflow and capture during
programming remain unqualified. Some require an independent VPW source or
receiver, a scope and controlled physical connection changes. No flash was
started to fill these gaps. The AL5 reader and unconditional write gate remain
unchanged.

Manufacturer reference: [OBDX DVI sections 3.10 and 3.11](https://obdxpro.com/Downloads/ReferenceManuals/OBDX%20Pro%20VT%20Reference%20Guide%20v2.pdf).
The examined document is the VT reference used as an API baseline, not a
promise that this GT firmware implements every filter identically.

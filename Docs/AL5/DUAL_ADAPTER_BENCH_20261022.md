# Dual-adapter bench observations, 2026-10-22

The user confirmed an isolated bench ECM, OBDX Pro GT and OBDLink SX joined
through a Y splitter, with no read or write running. The ECM identity was not
independently queried; this report does not establish its operating system.
No loader upload, security access, speed negotiation, reset, erase or program
command was used. The AL5 write guard was not changed.

Adapter-local checks confirmed SX COM8 / STN1130 v4.0.1 / SX r4.2, selected
VPW protocol 2 at reported 10417 baud, and supply readback 13.7 V. GT COM9
reported firmware 1.0.2.0 and network OFF before inspection and after tests.

## GT listener, SX requester

The first setup stopped before the diagnostic request: zero mask ON echoed
`0400000001` but GET reported `0400000000`. Saved settings were restored and
network OFF confirmed. This differs from the retained October 11 observation
where the flag read back ON regardless of the requested value.

The capture tool now preserves the currently reported mask flag while setting
all three mask bytes to zero, and requires exact full-setting readback. A
disabled mask or an enabled zero-bit mask has no required header bits under
the manufacturer's documented mask semantics. Unknown layouts and nonzero-bit
readback mismatches still fail before LISTEN ONLY; no mismatch is ignored.

The second attempt entered verified LISTEN ONLY at 1x. The SX sent one `0100`
request using explicit header `686AF1` and received `41 00 98 3B 00 15`.
The GT delivered **zero network frames**. Reception with this GT configuration
is therefore unproven. The cause remains unresolved; successful setting
readback does not establish a working receive path. Cleanup confirmed OFF and
exact restoration of saved settings.

## SX listener, GT requester

SX accepted `ATH1`, `ATIFR0`, then `STMA` and stayed in monitor mode. After
monitor entry, the GT was enabled at fixed VPW 1x and sent exactly one fixed
OBD-II PID-support frame `68 6A F1 01 00` (adapter supplies CRC). SX output:

```
68 6A F1 01 00 17
48 6B 10 41 00 98 3B 00 15 76
08 FF 10 03 58
08 FF 10 03 58
```

The request and matching ECM response establish decoded SX reception of this
short 1x exchange, with two additional broadcasts observed. They do not prove
electrical silence, every frame's delivery, or a sustained loss-free capture.
GT network OFF was confirmed before stopping the monitor. SX exited after one
non-CR `x` byte and returned a prompt. GT saved settings were restored.
SX volatile settings remain headers ON, IFR OFF and transmit header `686AF1`;
their prior values were not available for exact restoration. No persistent
settings save or adapter reset was issued.

## Reproduction and limits

`Tools/AL5/bench_dual_adapter_probe.py` is a separate bench-only tool. Default
`--listener gt` uses SX as requester; `--listener sx` reverses roles. It
requires explicit ports, `--bench-ecm-confirmed` and a new output file. The GT
must already be in DVI mode. The original capture client's transmission guard
remains unchanged; the separate bench sender accepts only network ON and the
fixed PID-support frame. There is no arbitrary payload option or programming
path. Do not run concurrently with a reader or writer.

Raw evidence is ignored under `LocalOnly/AL5/bench-*-20261022-*.jsonl` and
`Tools/AL5/LocalOnly/OBDLinkSX_20261014/bench-inspection-20261022-01.json`.
`DUAL_ADAPTER_BENCH_20261022.json` pins the raw log hashes and records outcomes.
The original bench driver did not record its source hash; a later small edit
retains partial monitor data on failure and clarifies labels. No claim of an
exact executed-source pin is made for this initial test.

69 offline tests passed covering capture guards/cleanup, speed evidence,
adapter-local inspection, USB-only monitor probe and the new bounded bench
query guard. Hardware observations above are separate from those tests.

No flash or full read was attempted. 4x reception, transition continuity,
buffer/throughput limits, IFR suppression on the physical wire, electrical
loading and non-interference during programming remain unqualified. Decoded
logs from two adapters cannot independently exclude short pulses or contention;
physical bus measurements are needed for that stronger claim. An actual flash
must not be the first test of these unresolved properties.

Sources: [OBDX reference sections 3.5, 3.10.2 and 3.11.5](https://obdxpro.com/Downloads/ReferenceManuals/OBDX%20Pro%20VT%20Reference%20Guide%20v2.pdf),
[OBDLink reference sections 7 and 8.9](https://www.scantool.net/scantool/downloads/682/obdlink_frpm_f.pdf).
The latter is a modern command reference; command acknowledgments and the
observations above provide the narrower evidence for this older SX firmware.

# Offline OBDX speed-transition evidence

The capture tool's `replay` mode now includes `obdx_speed.py`, an offline
interpreter of original DVI receive bytes and recorded adapter-local requests.
It emits `speed_evidence` records and a source-hashed `speed_analysis` summary.
It never opens a serial port, negotiates a bus rate or changes logger settings.
Live capture remains fixed-speed; automatic speed following is disabled.

## What the existing code establishes

`Apps/PcmLibrary/Messages/Protocol.Speed.cs` creates four-byte physical-header
requests `6C <destination> F0 A0` (permission) and `6C <destination> F0 A1`
(begin). It parses E0 permission replies and 75/7F refusals.
`Vehicle.Kernel.cs:511` actively negotiates permissions, sends the begin command,
checks refusals and then changes the adapter setting. Its active exchange and
timing cannot be copied into a passive logger without separate validation.

`Devices/OBDXProDevice.cs:877` changes the DVI speed setting; its comment explicitly
distinguishes that setting from changing the controller. The manufacturer's
[reference section 3.11.6](https://obdxpro.com/Downloads/ReferenceManuals/OBDX%20Pro%20VT%20Reference%20Guide%20v2.pdf)
documents explicit 1x/4x selection. The examined reference does not establish
GT automatic speed detection, simultaneous dual-rate capture, switching delay
or transition continuity. Absence of those claims is not proof of incapability.

`AL5ReadOnlyProbe.cs:111` records prior AL5 acknowledgment followed by failed 4x
identity reads and retains 1x. This is an existing project observation, not a new
hardware test. PcmHammer's generic negotiation patterns are not a proven EFILive
AL5 programming/recovery speed-transition contract.

## Interpretation rules

The analyzer separates the following evidence:

- An outgoing DVI speed SET invalidates current readback certainty. A matching
  echo is an acknowledgment, not an independent configuration readback.
- Only a checksum-valid speed response correlated with a recorded GET establishes
  the reported adapter setting. Unknown, unmatched and overlapping responses
  preserve uncertainty; rejected or unfinished requests remain explicit risks.
- Responses while the reported network is OFF are labeled adapter-local
  configuration. A 1x/4x/1x setting sequence never becomes a bus-transition claim.
- Network negotiation candidates require the documented PcmHammer 6C header,
  off-board tool address, service and exact request shape. Permission/refusal
  context must match the tool and target. Foreign tools, unrelated service bytes,
  A2 programming prompts and unrelated priority forms do not trigger switching.
- CRC presence is taken from recorded DVI CRC-display status. An unknown layout
  remains ambiguous: a CRC byte must not masquerade as an A0/A1 service. The VPW
  CRC itself is not independently checked by this analyzer.
- An A1 candidate without a separate adapter 4x readback, or after a refusal
  candidate, produces a **potential** capture-gap finding. It is not evidence
  that the physical transition occurred, failed, or caused a measured packet loss.
- Frames arriving while reported OFF are flagged as contradictory/stale evidence.
  Buffered frames, serial delivery delay and unknown timestamp byte order prevent
  assigning a physical switch time from these records.

Every event retains its receive packet ordinal and ending source JSONL line;
readbacks also retain the corresponding request line. Fragmented frames keep
their ending source position, and verified packets survive later corruption.
The final summary always reports actual bus speed as unknown, automatic tracking
as false and transition continuity as unproven. It does not emit executable
commands or propose an unvalidated delay-based speed-follow algorithm.

## Use and validation

```powershell
# From Tools/AL5; output must be a new file.
py -3.13 obdx_capture.py replay --input saved_capture.jsonl --output speed_replay_new.jsonl
py -3.13 -m unittest -v test_obdx_capture test_obdx_speed
```

Thirty-nine offline tests pass. Speed-specific coverage includes independent
readbacks, acknowledgments without GET, mismatched readbacks, incomplete and
overlapping requests, CRC ambiguity, refusal context, unrelated traffic,
fragmented/coalesced packets, partial facts and replay through the public CLI
with serial access forbidden.

The real retained GT local-probe log reconstructs three speed readbacks
`1x, 4x, 1x`, two setting requests and two echoes, all with reported network OFF.
It contains zero network packets, zero negotiation candidates and zero gap risks.
This establishes correct interpretation of actual adapter-local records, not
real-provider bus capture. Original logs and replay outputs remain ignored under
`LocalOnly/OBDXCapture/`; [the evidence report](OBDX_SPEED_CHECKS_20261011.json)
pins input, analyzer and relevant PcmHammer source digests.

No adapter was opened or commanded during this work. The previously verified
OFF state was not changed. Existing AL5 reads and write gates were not modified.
Before live speed following could be enabled, independent evidence must establish
the actual EFILive transition sequence, logger behavior at both rates, switching
latency, loss/overflow reporting and return-to-1x behavior. No deliberate flash
interruption or speculative bus negotiation belongs in that validation.

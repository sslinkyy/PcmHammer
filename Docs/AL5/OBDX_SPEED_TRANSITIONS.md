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

Fifty offline tests pass. Speed-specific coverage includes independent
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

## Delayed replies and incomplete evidence

Overlapping speed requests or an adapter error while awaiting a speed reply make correlation
unusable for the rest of that log. DVI speed replies have no request identifier;
a later apparently fresh GET cannot distinguish a delayed older reply. The tool
does not invent a timeout or assume that a particular reply drained the queue.
Unknown speed-status formats also retain this uncertainty. A separate recording
is required for new correlation context; that alone does not prove hardware
queues were cleared.

A begin candidate consumes its permission context. Repeated begin commands do
not reuse earlier grants. Network-state changes and reported OFF clear that
context; network bytes delivered while reported OFF remain raw facts and a stale
or contradictory-evidence risk, rather than new negotiation context.

Replay writes its final summary even when JSON, framing or EOF validation fails.
Earlier verified packets and observed readbacks stay in the output, while final
adapter certainty is invalidated. The summary records examined bytes/lines,
`examined_sha256`, remaining undecoded DVI bytes, the error and `replay_complete`.
`input_sha256` is populated only when EOF was reached; otherwise it is null.
A truncated DVI packet at EOF can therefore have a full source hash while replay
remains failed. This separates source coverage from successful interpretation.

Missing or failed terminal source results invalidate final speed certainty.
Records after a terminal source result fail replay instead of letting an earlier
success marker qualify a different or incomplete stream. None of these checks
claims packet-loss measurement or physical transition success.

The [follow-up replay report](OBDX_SPEED_REPLAY_CHECKS_20261011.json) pins the
updated analyzer and replay implementation. The original GT local probe still
replays as 1x/4x/1x adapter configuration, with zero vehicle packets and no gap
risks; its entire source was examined and its terminal result preserved.

## Evidence qualification

The final `speed_analysis.qualification` reports recorded vehicle-frame counts,
frame associations with the last confirmed adapter readback, readback counts by
OFF/other configuration scope, and readbacks recorded in a reported receive
context. A frame associated with a 4x adapter readback is not a measured 4x frame:
it could be buffered or delayed. The counts preserve that distinction.

`missing_recorded_evidence` identifies absent negotiation candidates, receive-
context readbacks and frame associations. `unverified_physical_evidence` separately
lists per-frame bus rate, switching latency/loss, dropped-frame/overflow accounting,
physical return to 1x and the controller-specific programming speed sequence.
Those cannot be established from this DVI record format alone. All existing gap
risks remain in `blocking_risk_counts`. `live_speed_following_ready` remains false;
this report is not authority to switch a logger or program a controller.

Malformed or unsupported network-state and CRC-display status replies now erase
the previous interpretation and clear negotiation context. A subsequent frame
cannot inherit the earlier CRC layout or permission grants. Unknown network state
still permits raw protocol-candidate reporting, never receive qualification.

Tests include a complete-looking synthetic negotiation with readbacks and frame
associations at both adapter settings and no gap findings. Its missing-recorded
list is empty, but its physical evidence remains unverified and live readiness
remains false. The saved real GT local probe has only OFF-context readbacks and
therefore lacks every recorded vehicle/negotiation requirement. The
[qualification report](OBDX_SPEED_QUALIFICATION_20261011.json) pins that replay
and its implementation. No hardware was opened or commanded for this extension.

# E54 source-F0 capture and GT filter coupling, 2026-10-29

The third AutoCal E54 bench read completed successfully in 2:00 with GT
listening at fixed 4x and filtering source byte `F0`. All six displayed segment
checksums match the earlier reads. Its 128 data blocks cover the same 524,286
bytes, `0x000000-0x07FFFD`, with identical contents and valid block checksums.
The final two flash bytes were not transferred. No flash operation was started.

## Source byte is not physical sender identity

GT recorded 263 frames with source byte `F0`; all physical VPW CRCs pass.
All 132 requests in the selected host-trace window match an ordered subsequence
of the capture, with zero missing requests. The additional captured
frames are 129 copies of `8C FE F0 3F`, one `6C 10 F0 3F`, and one
`6C 10 F0 3C 55`. These extras remain in the evidence. The complete GT stream
is not identical to that host-trace window and must not receive a strict pass.

The uploaded E54 read loader contains a routine at `0xFF95CA` that writes
`8C FE F0 3F` through the same VPW transmit registers used for ECM responses.
Its data-send completion path calls that routine at `0xFF953C`. The capture
contains that frame after each of the 128 block requests. Static code and
the observed ordering strongly support ECM-loader origin for those frames;
the `F0` header alone cannot identify AutoCal as their physical sender.
The additional startup copy and the `6C 10 F0 3F` origin remain unresolved.
The `3C 55` request occurs after the comparison window's last data block.

The loader is 1,174 bytes loaded at `0xFF9200`; its SHA256 is
`e2726849cc006ee7602c3391e7c39182627639edbb98d99f1392642ed5bee2a6`.
This is evidence about an E54 read loader, not the AL5 programming kernel.

Strict replay consumed all 622 capture lines: 263 network frames, 57 adapter
frames, zero adapter errors, zero outgoing guard violations and no undecoded
bytes. Every network frame is associated with a recorded 4x adapter setting;
physical pulse timing was not independently measured. Capture cleanup verified
network OFF. The user confirmed ignition OFF, and EFILive was observed past
its countdown with the saved third read open and all six segment checks valid.

## Filter coupling with the network OFF

The adapter-local probe recorded 16 observations and queried all five filters
after every change. Its 190 adapter replies contained 66 network-state replies,
all OFF; it received no network frames and issued no vehicle-send or listen
command. The current GT firmware reports:

- Exact TO, exact FROM and mask enable flags change together with the last
  exact-filter setter. Requested independent TO/FROM flag states are not
  independently retained in these readbacks.
- TO ON sets the destination mask byte to `FF`; FROM ON sets the source mask
  byte to `FF`, retaining an existing destination mask byte.
- Setting the mask changes its three mask bytes. Neither requested mask enable
  value changed the shared reported enable flag in this probe.

This explains the earlier mask echo/GET disagreements and why applying a
zero mask before an exact-source setter does not leave the mask at zero.
It supports a shared filter-state interpretation; hidden firmware storage
and effective receive behavior remain separate unknowns.

All nine final GET payloads match their original values. This is observable
readback restoration only: a getter alias could conceal a changed stored flag.
The probe reports hidden-state restoration as unknown, not successful.

An experimental all-source candidate enables the exact FROM filter first,
then writes the enabled zero-bit mask last and verifies the complete resulting
filter readbacks. It requires a separate reception test before qualification.

## Tools and retained evidence

`Tools/AL5/compare_vpw_read_capture.py` compares a closed GT JSONL capture and
matching E54 HTX without opening a serial port. It retains exact ordering,
checksums, coverage, scope failures and extra frames. `probe_obdx_filter_links.py`
uses a narrower OFF-only adapter command guard and preserves echo versus GET
disagreements as observations.

Private captures, HTX, saved CTZ, receipts and loader analysis are retained in
`LocalOnly/autocal_request_20261029_01`. The first capture in that folder was
canceled before a new read began because the previous CTZ was unsaved; it is
not counted as a successful reception test. The successful capture is
`gt_autocal_4x_attempt02.jsonl`. The third CTZ is retained as
`request_3_E54_0000.ctz`; the preceding read was also saved separately.

The companion [JSON report](AUTOCAL_GT_REQUESTS_20261029.json) pins the evidence. Neither this test nor the earlier
source-10 capture establishes simultaneous bidirectional reception, speed
transition continuity, electrical noninterference, flash capture or recovery.
Live AL5 writes remain disabled.

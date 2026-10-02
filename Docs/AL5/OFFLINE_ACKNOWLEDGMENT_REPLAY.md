# Supplied-event block acknowledgment replay

`Tools/AL5/replay_acknowledgments.py` adds offline ordering checks after the
whole-batch preflight in `host_validation.py`. All frames, status bytes and
readback bytes are supplied by the caller. It has no adapter, sender, packet
constructor, session entry, erase, reset or file output. The planner hashes the
implementation without opening any physical verification gate.

Preflight requires a valid baseline and complete checksummed modeled candidate.
The replay progresses through ready, awaiting status, awaiting block readback
and awaiting final snapshot. An issue event must name the next block index;
only one block can be pending. A six-byte software response must match the
request priority, tester destination, module source and `0x76 00 73` body.
That status moves to awaiting readback, not directly to the next block.
Readback must match the exact pending payload; the final snapshot must match
the complete candidate and its native checksum.

Unsolicited/duplicate responses, malformed headers, truncated responses,
non-success statuses, ordering violations and readback mismatches abort.
Timeout/disconnect also abort with unknown physical write outcome. A replay
that ends early is incomplete. Automatic retry stays false in every result.

## Correlation limitation

The recovered status body has no verified block sequence field. Synthetic
success responses for two blocks can be byte-for-byte identical. A duplicate
while no response is pending can be rejected, but a stale identical response
arriving during the next pending block cannot be identified from these bytes.
The replay indices are local event tags; they do not invent a sequence number
on the wire. Matching supplied readback remains mandatory, and physical
acknowledgment correlation and physical readback verification remain false.

Eight tests cover complete supplied replay, status without readback, duplicate
and unsolicited statuses, header/truncation/failure cases, timeout/disconnect,
wrong block readback, wrong final snapshot, incomplete/preflight rejection,
identical statuses across blocks and the planner's closed gates. Completion is
reported as `offline_complete`; readiness remains false with null erase scope
and empty packet lists. Tests supply synthetic software bytes only and perform
no hardware access.

This is a block-order model. It does not close the session/loader/erase/exit
protocol or establish physical framing, receive capacity, collateral
preservation, timing or recovery. Next connect an independently complete saved
session transcript to these rules if one exists and establish response/readback
correlation from physical evidence before considering a live transport.

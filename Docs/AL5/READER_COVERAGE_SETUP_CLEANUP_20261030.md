# Reader coverage and captured vehicle setup/cleanup

## Reader review

`AL5CalibrationReader.ReadCalibration` is fixed to `0x08000..0x15FD7` inclusive:
57,304 bytes, 14,326 four-byte requests plus a high-address preflight at `0x158A8`.
It does not read collateral or the final marker. `ReadDword` is private; there is
no supported arbitrary-range interface to invoke. The working reader is unchanged.

The missing snapshot range is `0x15FD8..0x1FFFF`, 41,000 bytes: 40,998 collateral
bytes plus the two-byte marker. It is four-byte aligned at both ends and would
require 10,250 additional dword reads. The final request would start at `0x1FFFC`,
returning two collateral bytes and the two marker bytes. These arithmetic facts
do not establish that the controller permits reads of every address in that range.

The reader sends a 24-bit address but the observed reply echoes only its low
16 bits. Its `0x158A8` anchor proves useful high-address behavior at that location,
not all address banks or collateral readability. Stale replies with the same
low-16 echo cannot be distinguished by the echo alone. Queue clearing and one
outstanding request reduce ambiguity; they are not proof of full address identity.

The current parser accepts lengths >=10 (or >=11 for its hypothetical full-24
echo branch), then takes the final four bytes. This permissive future-format
fallback is another reason not to expand the live range by changing constants:
an extension should use explicitly qualified exact reply shapes, preserve source
identity and reject extra/truncated bytes. The calibration BE16 sum and anchors
must remain scoped to the calibration; applying them to the whole snapshot would
not validate collateral or prove a marker.

`AL5SavedReadCoverage` supplies only offline range metadata and exact-size saved
file assembly. It requires 57,304 + 41,000 bytes and preserves all supplied bytes,
including an incorrect marker. It cannot open a vehicle, build requests or enable
the extended reader. Broader live reading and readability are explicitly false.

Before a later read-only qualification, remaining evidence needs include actual
Mode 23 range/permission semantics, exact receive framing and full-address
alias/stale-response handling. No new live read is authorized by these findings.

## Vehicle setup and cleanup integrated

The exporter now preserves every VPW message in the observed AL5 wrapper context,
including unknown messages, so the C# replay validator must accept or reject it.
It no longer filters away security and broadcasts. Adapter-local USB configuration
and other RX wrapper contexts remain outside this rehearsal; it is not an adapter
initialization implementation.

The rehearsal requires the captured `3C 55` query/reply, broadcast `20`/`60`,
three serial-block queries, seed reply, key request and `67 02 34` response before
boot requests. It validates direction, prefix, extent and order. Serial values
and the seed/key relationship are not authenticated or derived, and the code
does not calculate or send keys. `SecurityAuthorizationProven` remains false.

Between the boot exchanges it requires `28 00`/`68 00`; after loader OS identity
it requires the loader serial queries. During programming it records the observed
`28 00` broadcasts without consuming the pending block or manufacturing an ACK.

After finalization the new `Cleanup` state requires the `3C 55` query/reply,
allows an observed identical query repeat, then requires `20`/`60`, `68 6A F0 04`
with `48 6B 18 44`, and the final `6C FE F0 14` broadcast. Only then is saved-file
verification available. Sessions 02 and 05 also contain `6C F0 18 7F 14 23`;
this single specifically matched response is recorded without turning it into a
programming failure or claiming successful execution of service 14. Session 04
has no such reply in its HTX. Neither absence nor that rejection proves cleanup
success, reset recovery or electrical silence. `CleanupObserved` means the
required captured traffic was observed, not that every service succeeded.

Unexpected negative setup replies stop the rehearsal. Unknown payloads, skipped
setup, missing cleanup, duplicate final replies and wrong ordering cannot silently
advance it. The 192-block and saved-verification gates remain intact.

## Validation

All three real captures pass production C# replay with 460, 475 and 466 selected
frames. Each still has 192 positive block replies and 15/20/19 checksum-error
repeats. Tests exercise 15 interruption boundaries per capture, missing cleanup,
negative setup, optional rejected cleanup, exact supplemental size and marker
preservation. Export tests preserve unknown VPW messages for validation.

Library build and all 210 null-vehicle write-gate cases pass. The build retains
three pre-existing async-without-await warnings. Raw corpora remain local and
ignored. No live reader, writer, adapter or vehicle operation ran.

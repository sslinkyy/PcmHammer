# Mode 23 supplemental range and response identity

Offline evidence only. The existing live reader range and all AL5 live-write
gates remain unchanged. No adapter or vehicle was accessed.

## Native observations

The saved HIGH firmware SHA-256 is
`492040d9460d53b77dda606b9a89f4254e0680f239093001663f6ed5cf51ba75`.
The existing service table identifies handler `0xBFDA0`. Its permission helper
`0xC00E8` calls region lookup `0xC2F88` and end-bound check `0xC2FD0`.
The table at `0xC591E` contains inclusive ranges `0x000000..0x0FFFFF` and
`0xFF8000..0xFFB7FF`. The end check includes all four requested bytes. Additional
per-byte exclusions are `0x3FD8..0x3FDB` and `0xC4C66..0xC4C67`.

The handler requires internal message length 8 and count 1, constructs the full
24-bit request address, and checks four-byte permission before reading. Failed
length/count checks call the negative formatter with `0x12`; failed permission
calls it with `0x31`. Accepted requests copy four data bytes and only the low two
request-address bytes into the six-byte response buffer, then set pending bit
`0x10`. The response formatter and transport scheduler were not executed.

## Executed offline evidence

`Tools/AL5/emulate_mode23_coverage.py` pins firmware identity before importing
Unicorn or allocating memory. It executes only the selected native functions,
with an instruction budget, read-only firmware/data pages, synthetic RAM and
stack, and an intercepted negative formatter. Code digests and results are in
`MODE23_COVERAGE_20261030.json`.

All 10,250 dword requests from `0x15FD8` through `0x1FFFC` pass the native
permission helper. This covers the missing 41,000 bytes, including the two-byte
tail marker. Boundary tests reject crossing a region end and overlapping an
excluded byte. Handler samples verify returned synthetic bytes, pending flag,
negative reasons, and untouched response storage on rejection.

Requests at `0x08000` and `0x18000` deliberately use identical synthetic data:
both produce the same response body. Thus a matching low-16 echo cannot prove
which address bank produced the response. This is a protocol limitation, not
evidence that the handler ignores the high address byte.

## Offline parser and remaining qualification

`AL5SavedMode23Reply` accepts exactly the known ten-byte positive VPW message
(header/service, low-16 echo, four data bytes; transport CRC already removed).
It rejects truncated, trailing, and hypothetical full-24-bit response forms.
Negative Mode 23 replies retain their reason. Matching results are explicitly
named `MatchingLow16Echo`, never full-address verification. Data is copied so
later buffer reuse cannot change an accepted result. No live reader calls this
new parser yet.

This resolves the native range-helper question from
`READER_COVERAGE_SETUP_CLEANUP_20261030.md`; it does not establish dispatcher,
security-state, scheduler, or physical read qualification. A future reader must
serialize requests, handle stale responses and retries, preserve negatives and
gaps, and retain the address-bank ambiguity in its evidence. The remaining bytes
have not been read from the installed controller or replaced with captured
write data. Live reads beyond the established range and live writes stay disabled.

## Validation

The pinned native emulation, saved-report and changed-firmware rejection tests,
production C# offline parser/image tests, library build, and all 210 null-vehicle
write-gate cases pass. Library build retains three existing CS1998 warnings.

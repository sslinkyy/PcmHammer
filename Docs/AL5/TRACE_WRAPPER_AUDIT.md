# All binary wrappers in the existing write traces

[The audit](TRACE_WRAPPER_AUDIT.json) inventories every binary record in the five
saved AL5 write containers. All 709 binary records match the established
channel-1 `0154` or channel-2 `0152` wrapper shape and length rule. There are no
unsupported binary wrappers in these files. This narrows the possibility that
the earlier request census omitted programming traffic because of an unknown
binary wrapper.

The message-header filter includes priorities `6C`/`6D`/`8C`, module/global
destinations and both tester addresses `F0`/`F1`, plus the corresponding module
responses. No framed Mode `36` erase (`EE`), word-program (`00`) or finalize
(`FF`) request is observed, and no framed Mode `76` response is observed.
The existing loader uploads remain present as subtype `80`.

These files do not establish the complete programming exchange needed by the
offline acknowledgment model. Complete container decoding is not evidence of
complete bus capture; dropped or unrecorded traffic, other files and interface
checksum behavior remain unresolved. The filenames and missing commands do not
establish a flash outcome or prove that no destructive activity occurred.

## Diagnostic policy and reproduction

Unknown binary wrappers, if supplied later, are scanned for recognizable header
signatures. Such hits remain diagnostic only: loader or tune bytes can resemble
message headers. They cannot become framed requests, physical acknowledgments
or a verified session. Synthetic tests enforce that distinction and exercise
global/F1 addressing that the earlier narrow decoder did not recognize.

Run `Tools/AL5/audit_trace_wrappers.py --trace <saved-W-HTX> --trace <another>
--output <report>`. The output contains wrapper counts, short service identifiers,
source hashes and explicit uncertainty; private text and payload bytes are
omitted. The planner hash-links this report and retains false exchange/transport
verification, false readiness and empty packet lists.

The next useful source is an already recorded complete AL5 programming exchange,
or independent saved interface/firmware evidence that closes the missing
physical behavior. Do not generate a destructive capture on the only installed
TCM to fill this gap. Offline protocol reconstruction, preservation analysis and
read-only vehicle baseline work can continue.

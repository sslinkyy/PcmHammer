# Saved AL5 write-session chronology

[The audit](SESSION_CHRONOLOGY.json) preserves all-record ordinals, decoded file
offsets, relative timestamps, source/message hashes and route-compatible
preceding candidates. Direction remains inferred from the known host wrappers.
It does not export request contents, security values or loader payloads.

Four of the five existing W traces contain two Mode `34` request candidates,
two exact `74 44` response candidates, then one subtype `80` loader-upload
candidate. The fifth contains none of these events. The two requests occupy
different positions in each container; the audit retains both preceding
candidates rather than assigning a unique response/session pairing.

The [application boot analysis](APPLICATION_BOOT_ENTRY.md) establishes that
startup and boot-dispatcher paths can produce the same `74 44` response with
different upload-arming state. Recorded bytes therefore cannot establish
arming, application entry, physical timing or loader execution. Earlier
responses may also be stale or unrelated. A container's complete decoding is
not a complete physical programming capture, and a trace filename is not an
operation outcome.

`Tools/AL5/audit_session_chronology.py --trace <saved-AL5-W.htx> --trace <another>
--output <report.json>` reproduces the audit. It shares the complete wrapper
parser with `audit_trace_wrappers.py`; unknown wrappers and wrong directions
cannot become session events. No time cutoff manufactures unique pairing.
Nonmonotonic timestamps remain explicit and never reorder source records.

Tests cover route variants, global/F1 requests, missing requests/responses,
repeated responses/retries, wrong routes, malformed wrapper lengths, record
ordinals, nonmonotonic timestamps and all closed live gates. The planner links
the saved report by hash without promoting session state. Continue static
callback/object analysis and independently close physical transport,
preservation and recovery before any executable writer can be enabled.

Schema 2 stores each candidate ordinal once in a shared tester-route index.
Per-event prefix references select only candidates preceding that record,
keeping all candidates and ambiguity with linear storage/serialization.
A 5,000-session stress regression covers representation expansion; orphan
response counts remain scoped to each tester route.

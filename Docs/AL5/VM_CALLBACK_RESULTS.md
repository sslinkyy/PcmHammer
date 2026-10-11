# AL5 host callback results and remaining flash evidence

Offline static analysis, 2026-10-11. Source hashes and bounded instruction windows
are in [VM_CALLBACK10_STATIC.json](VM_CALLBACK10_STATIC.json) and
[VM_CALLBACK_OUTCOMES_STATIC.json](VM_CALLBACK_OUTCOMES_STATIC.json).
No application, IPC, callback, adapter or controller was executed.

Hapi selectors 0x0B, 0x0C and 0x0D all reach 0xA548E3. The selector predicates
enable send only, send-and-receive, and receive only respectively. Sending reaches
A16CC8 (or A16CA8 for zero payload); receiving reaches A170DC/A170F8. The returned
payload length is stored at shared +0x14, metadata at +0x16, and payload at +0x1E.
ScanAndTune BBC408 copies the 26-byte shared header and payload back when the
SendMessage result is zero. BB0614 returns the resulting zero-extended word length.

Typed Hapi exceptions store raw exception status +0x18 in the message result;
unrecognized exceptions store 0x2D. ScanAndTune raises a local exception on a
nonzero SendMessage result. Constructor AF5510 preserves the supplied status at
exception +0x18. The BB06F8 handler returns -1 and copies that status to the
optional output pointer. This handler was decoded at its metadata-selected
landing address; linear disassembly through Delphi exception tables had produced
misleading instructions in earlier broad windows. Raw status codes remain raw;
their equivalence to controller responses or VM statistic values is not assumed.

The Hapi receive branch checks the 01 52 prefix, allows payload lengths up to
0xC000, retries invalid frame candidates up to fifty, and raises selected errors
for invalid length (0x108), exhausted header candidates (0x26), or checksum
mismatch (0x104). This pass has not reproduced the frame-checksum helper or full
lower transport behavior. Normal copyback is not proof of programming completion.

Selector 0x0A reaches A5488C -> A16BD8. When connected, device type 2 resolves a
handle and calls dynamically loaded FT_Purge with raw argument 3. Device type 3
clears local receive-buffer fields through A0DBBC -> A0F424 -> A0F7C8 under a
virtual lock. The selected handler does not store the purge function's return.
This is host transport cleanup. It does not establish controller reset, loader
exit, reprogramming, restoration, or recovery after interrupted erase/programming.

`Tools/AL5/replay_vm_callback_results.py` models only explicitly supplied callback
facts. It preserves signed-low16 VM result interpretation, status uncertainty,
the clamped destination copy versus separate full-length scalar, and the selected
mode1/selector1 negative-response flag. Nonpositive results with missing/zero
status and short copied payloads remain unknown instead of reading stale or
out-of-bounds bytes. Even a modeled positive payload cannot establish controller
acknowledgment. Saved [cases](VM_CALLBACK_RESULT_CASES.json) are synthetic vectors;
[replay](VM_CALLBACK_RESULT_REPLAY.json) is not a physical test. Inputs are
hash-pinned and existing outputs cannot be overwritten.

The user-selected project root was searched for additional evidence. The
[search inventory](PROJECT_EVIDENCE_SEARCH.json) records 23,506 paths and 96
archives, excluding .git and node_modules. No loose or archived named .htx/.blx/
.plx/.trace captures were found. The four external AL5 PcmHammer debug logs describe
read-only sessions. This filename/ZIP-directory search cannot exclude differently
named captures; source tunes, editor exports and reader dumps remain useful
references but do not prove programming/recovery behavior. The five earlier saved
W traces under the EFILive trace directory remain incomplete for that purpose.

To make an AL5 writer safely usable, the missing evidence is a full programming
exchange with exact affected-region readback and preservation verification, plus
interrupted-programming recovery validation. That requires existing equivalent
captures/readbacks or a spare AL5 and reviewed bench setup. The single installed
TCM is not an experimental target. Complete loader/session handoff, safe erase
geometry, durable marker handling and collateral/persistent-bank preservation
remain gates; no live authority is implied by the user asking for a finished writer.

The planner hashes these reports and keeps all write/retry authorization false,
erase scope unset, and packet lists empty. Existing readers and E54 behavior are
preserved. No flash-capable AL5 claim is made.

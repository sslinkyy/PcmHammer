# AL5 VM retry, failure and recovery tracing

Offline static evidence, 2026-10-11. Sources and exact hashes are retained in
[VM_FLAG20_STATIC.json](VM_FLAG20_STATIC.json),
[VM_RETRY_HELPERS_STATIC.json](VM_RETRY_HELPERS_STATIC.json) and
[VM_RETRY_FAILURE_AUDIT.json](VM_RETRY_FAILURE_AUDIT.json).
The latter matches selected instructions against the saved reconstruction;
it does not execute the VM, host callbacks or controller operations.

Native opcode 12 performs second-minus-first, writes through 404B30, then reads
the stored destination back through 404AF8 at 404DB0. Helper 4049D0 sets flag
0x20 if that result is zero and clears it otherwise. B1 truncates to unsigned
8-bit, B2 truncates to 16-bit and reads signed, and B4 stores 32-bit. Other flag
bits are preserved by this zero helper. Opcode 47 branches when 0x20 is set;
48 branches when clear. Immediately after the traced decrements, these are
zero/nonzero tests. They do not report unsigned borrow. Other helpers and
explicit mask operations also modify 0x20, so it has no universal numeric meaning.

Programming initializes B2 counter 0x217A to three at 0x1BBC. After a failure or
selected response, 0x1DD4 subtracts one, and 0x1DDE returns to 0x1CCA while the
stored result is nonzero. The isolated counter path is 3 -> 2 -> 1 -> 0.
At zero, 0x1DE4 sets error flag 0x80 and returns. Caller 0x2C54 then branches
to common error entry 0x2A00. The progress branch resets this counter to three.
The remaining-byte decrement at 0x1DB6 followed by 48 at 0x1DC0 likewise loops
while remaining bytes are nonzero; it is not a borrow condition.

Each programming attempt assigns the common exchange's B1 send budget 0x2476
to one before calling 0x0188. That helper calls sender 0x0044, then receive
opcode 61. Header mismatches decrement a separate B1 counter 0x247A, initialized
to eight, and receive again until it reaches zero. A failed send/receive or
exhausted mismatch counter decrements the send budget at 0x022A. Programming's
budget of one therefore reaches zero without the helper's inner resend path;
the helper sets 0x80 at 0x026C. Its return path resets the budget to three and
the timeout to 250, but the next programming attempt assigns budget one again.
These are static control-flow/counting facts, not observed bus attempts.

Response dispatch in the programming routine has distinct paths. Flags 0x81
at 0x1CEE call helper 0x028E before backoff. Extracted response field 0x77
branches directly to backoff/decrement at 0x1DCE, without calling 0x028E.
Field 0x73 takes progress at 0x1D78. Other values assign status 0x600 plus the
response field before retrying. The 0x73 progress branch proves no physical
readback, and these comparisons do not establish wire correlation or complete
controller response semantics.

Helper 0x028E passes inline bytes `6C FE F0 28 00` to opcode 60, then calls
receive-drain routine 0x0102. The inline payload is a source observation;
its controller meaning and physical effect remain unresolved. The drain copies
initial pool value 20 into B1 counter 0x24B2, calls receive 61 with timeout value
250, and breaks early on error flag 0x80. Otherwise it decrements and loops
until zero, for at most twenty counted receives. Cleanup restores timeout 250,
calls opcode 64, then clears mask 0x81 at 0x013C. The native opcode 64 invokes
external callback selector 0x0A; its physical operation remains unknown.
This helper can clear a receive failure flag before returning to the outer
counter decrement. Clearing flags is not evidence that a programming fault healed.

Native opcode 60 clears 0x81 before calling external selector 0x0B. Receive 61
clears the same flags, resets its separate length scalar, invokes selector 0x0D,
copies at most the destination B0 capacity, and writes the full callback length
to a separate scalar. Native status helper 404A28 clears 0x81, maps nonzero status
through 4034D4 to error flag 0x80, and can set flag 0x01 for selected negative
response signatures. Short payload bounds, callback ownership/correlation and
actual transport outcomes remain unverified. The audit never applies those
unchecked native buffer reads to arbitrary input.

Recovery remains partially understood. We have traced retries, receive draining,
flag clearing and the common error/stop route. We have not established restoration
after interrupted erase/programming, durable marker consistency, preservation of
collateral/persistent banks, power-interruption recovery, or safe controller reuse.
The earlier conditional recovery message is still not a recovery implementation.

`Tools/AL5/audit_vm_retries.py` requires hash-pinned flow and both native evidence
reports. It rechecks reconstructed source identity and selected instruction/pool
profiles, and emits exclusive JSON output with isolated counter models. Unknown
or changed profiles fail closed. The offline planner links the audit; automatic
retry authorization and live writes remain false, erase scope remains unset,
and all packet lists remain empty. Existing E54 and AL5 Mode 0x23 paths are preserved.

[Host callback result and cleanup tracing](VM_CALLBACK_RESULTS.md): selector0A is transport cleanup, while0B/0D route send/receive with separate exception status. Physical programming, preservation and interrupted-flash recovery remain unverified.

# EFILive AL5 host callbacks

Static observation from the installed ScanAndTune build resolves the host registration left open by the VM loader investigation. Source hashes, PE section mappings, imports, bounded dumpbin listings and the prior REA validator record are retained in `EFILIVE_HOST_CALLBACKS.json`. Neither EFILive nor its callbacks were executed.

The initializer at `0xBB0238` fills a 0x8C-byte table at `0x155B8F8`: offset +4 points to executor `0xBB0614`, offset +8 to validator `0xBB0744`. The registration call at `0xED838F` precedes vmLoad at `0xED83AC`. Addresses are build-specific virtual addresses, with file offsets retained separately. BSS is not file-backed.

The validation callback delegates to `0xA4106C`. Its entire 256-word table matches reflected polynomial `0xA001`; the helper takes a 16-bit caller seed and has no final XOR. VM validator `0x403380` supplies seed `0xB27D`, chaining code bytes [2,48), code [64,code_length), then all data bytes. It compares the result with little-endian code bytes [0,2); mismatch returns native status 0x503. Code [48,64) is excluded. Later logging callbacks and date compatibility checks remain outside the offline CRC model.

`Tools/AL5/validate_vm_buffers.py` reuses the existing CRC implementation for explicitly supplied post-transform code/data buffers. It pins both caller-supplied hashes, bounds allocations to VM capacities and preserves hashes for each range. Outputs distinguish a matching supplied-buffer CRC from verified object transformation or successful native validation. Existing raw object inspection remains framing-only. No transformed installed AL5 object is claimed.

The executor copies a request through receiver `0x155B988`, with a 26-byte exchange structure and data beginning at shared offset30. Its path reaches WaitForSingleObject, SendMessageW message `0x8000` to a shared HWND, and ReleaseSemaphore. This establishes an IPC boundary; recipient identity, selector semantics, transformation implementation and device dependence are still unknown. Calling this callback would not be an established local-only decoder.

Next investigation: resolve receiver initialization and the message 0x8000 handler statically. Programming exchange, collateral preservation, interrupted programming and physical recovery remain unproven. All write gates remain false; no packets, IPC or hardware operations are emitted.

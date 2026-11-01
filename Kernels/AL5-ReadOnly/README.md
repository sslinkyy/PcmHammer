# AL5 read-only callable core prototype

This is independently written experimental source, not an uploadable AL5 kernel. It is excluded from BuildAll and every live PcmHammer adapter/upload route. The C function needs a caller providing the M68K ABI and candidate scratch buffers; it has no receive loop, VPW framing, watchdog service, interrupt setup or boot/handoff code. Physical CPU/RAM/peripheral compatibility remains unqualified. Do not upload the text-only binary to a controller.

## Implemented contract

The core accepts only a 22-byte experimental payload. Bytes 0-1 are ASCII AR; byte 2 is version 1 and byte 3 is read operation 1. Bytes 4-11 hold a nonzero 64-bit host-session nonce, bytes 12-15 a BE32 sequence, bytes 16-18 the full BE24 flash address, and byte 19 a count from 1 through 32. Bytes 20-21 are CRC16-CCITT-FALSE over the preceding bytes (initial 0xFFFF, polynomial 0x1021; golden 123456789 gives 0x29B1).

Replies use ASCII ar, version 1 and status zero, followed by the same nonce, sequence, full address and count; then data and a CRC over the header and data. Reply size is 22+count, at most 54 bytes. These are core payloads, with no assigned VPW service or bus header. The prototype size bound is an engineering constraint, not proof that the AL5 transport can carry such a reply.

The core permits byte reads only in 0x000000-0x0FFFFF. It validates length, operation/version/magic, CRC, nonce, byte count, address/end bound, output capacity and candidate scratch addresses before reading any flash byte. Rejected calls return zero and do not emit a reply. It contains no erase/program/security/reset dispatch and no peripheral accesses. For emulator ABI containment, the request pointer must be 0xFFA500 and the reply pointer 0xFFA600; those addresses are NOT physically reserved or qualified on the AL5. Stack and code locations are also experimental.

AL5ReadOnlyCoreSession in PcmLibrary is an offline host validator with one pending request. It generates random nonzero nonces through CreateOffline, permits deterministic caller-supplied nonces for saved tests, and checks full request identity on replies. Never reuse a nonce across real sessions. Sequence numbers do not wrap; timeout/cancellation closes the session. Valid old/foreign replies remain unrelated, malformed own-protocol replies stop the session, and no automatic retry exists. A new payload design does not establish physical freshness until transport and execution are qualified.

## Reproducible offline build and checks

Requires an already-installed WSL M68K compiler; the script installs nothing. Choose a new output directory:

```powershell
python Tools/AL5/build_readonly_core.py --output-dir LocalOnly/al5_reader_new_build
```

The build validates a big-endian M68K ELF, extracts only the text section, rejects unexpected allocated sections and records compiler flags, source/header/ELF/code hashes, actual section base and callable entry. It does not copy anything into the deployed Kernels/build directory. Current WSL GCC 11.4.0 with -m68020 produces 392 bytes at text base 0xFF9006, function entry 0xFF9046, code SHA256 459a4c4380d5a7992f2239294701b8048f7dd16e9dc93c15dee6b77854c1b0a6. Hardware instruction-set compatibility is a separate gate.

Use emulate_readonly_core.py with Unicorn M68K available in the selected Python environment, passing the emitted code and entry. The harness enforces read-only synthetic flash, permits writes only in reply/stack ranges, forbids escaping the compiled code, and bounds execution. It tests reads at flash endpoints, both address banks and the six stock-service-excluded bytes, plus invalid length/CRC/count/nonce/range/capacity/pointer inputs. Emulator memory does not prove those excluded addresses physically readable.

ReadOnlyCoreSessionTest.csproj accepts the emulator JSON report to validate the exact machine-code reply vectors through production C# code and compare host request bytes. The original Mode 23 reader and writer remain unchanged. Native C/Python and C# checks agree on the independent standard CRC golden vector.

## Remaining work

Implement and verify a separately bounded VPW transport/entry bridge, watchdog behavior, interrupt/handoff behavior and RAM ownership before considering a hardware test. Prove that complete token/address fields survive the actual adapter path. Qualify on a recoverable spare AL5 before using the installed truck controller. No live upload or execution route is present in this prototype.

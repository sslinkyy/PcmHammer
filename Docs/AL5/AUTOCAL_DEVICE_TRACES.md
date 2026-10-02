# AutoCal V2 device traces: supplied files remain undecoded

The user supplied `USR_0057.efx` and `USR_0059.efx` from the local EFIlive scans
folder. Each is 44,571 bytes; their SHA256 hashes differ. The originals stay
outside Git. The [metadata inventory](AUTOCAL_DEVICE_TRACE_INVENTORY.json)
contains hashes and bounded probe results without private header fields,
identifiers, tune bytes or raw trace data.

The user subsequently confirmed that EFILive encrypts these files. The inventory
records this as user-provided provenance. The cipher, keys and encrypted-body
boundaries have not been independently established; failed compression probes
do not identify an encryption algorithm. Do not continue guessing compression
variants as though they constitute a decoder.

The user reports AutoCal V2, used both standalone and with a PC, and no spare
TCM. The supplied calibration-summary screenshot reports hardware 15183963,
OS 15184109, transmission calibration 15183960 and checksum 4E35D040. These are
user-provided software metadata, not identification of fitted MCU/FIFO/flash
chips or verification of current physical backups. VIN and serial are omitted.

## Findings and limits

Both files begin with the observed ASCII signature `V03VPW`. They do not decode
with the existing HTX transform/zlib/header parser. A separate bounded probe
tests fixed byte rotations/XOR keys and zlib offsets 0–255, with a 1 MiB output
limit. Neither file yields a complete stream under those combinations. Applying
the known HTX additive/rotation/XOR transform at those offsets also yields no
complete stream. These tests exclude only the tested combinations.

No literal module/tester header signatures from the six tested F0/F1 variants
appear in either supplied body. Because the bodies are undecoded, this says
nothing about whether programming traffic exists inside them. Even a literal
signature match would be diagnostic only until record framing is proven.
Equal file sizes do not establish duplication, capture capacity or completeness.
High entropy does not establish encryption. The header does not establish AL5
identity, operation type, success or failure.

The previous [HTX audit](TRACE_WRAPPER_AUDIT.md) remains scoped to the five PC
write traces. Its absence-of-framed-programming findings cannot be extended to
these EFX files. Conversely, merely supplying EFX files cannot close protocol,
acknowledgment, preservation or recovery gates. The planner now separately
hash-links the device inventory and keeps all write gates closed.

## Manufacturer context and next step

[EFILive's AutoCal V2 trace documentation](https://service.efilive.com/kb/articles/autocal-v2-trace-file)
describes device traces as recent-message buffers saved into the Scan folder.
Errors trigger automatic saving; successful operations may need manual saving.
Power-off/reboot and saving clear the RAM buffer. In pass-through use, EFILive
describes both PC and device trace saving. This does not promise a complete
programming capture or provide a public decoder in that article.

The user reports no decoded export or available decoding method. Continue
offline format analysis from these exact files and existing installed artifacts;
do not repeatedly request an unavailable export. The initial read-only scan of
installed V8 executables found no literal `V03VPW`/`V03CAN` signature; the one
`.efx` UI reference describes saving device traces, not decoding them. This is
only a string census and does not establish that a decoder is absent. No
installed executable or firmware was run or modified for that check.

Establish a decoding method and record framing before treating these files as
protocol evidence. Operation/outcome
context from the user can guide interpretation but cannot substitute for decoding.
An EFILive-supported decoded export would be another route if one becomes
available; no support message was sent. Do not create another flash on the only
TCM just to test trace completeness.

Reproduce metadata with `Tools/AL5/inspect_device_traces.py --trace <USR_0057.efx>
--trace <USR_0059.efx> --user-reports-encryption --output <report>`. No hardware is opened, no packets are
emitted, and output cannot overwrite a supplied input.

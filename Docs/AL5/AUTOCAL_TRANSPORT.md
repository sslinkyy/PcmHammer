# AutoCal V2 transport reconstruction, 2026-10-30

PcmHammer now contains an experimental AutoCal V2 device backend, a bounded
host channel and a Windows D2XX transport. The pinned 2,027-byte E54 RAM kernel
has now returned its exact expected version through that backend, acknowledged
exit, and returned ordinary OS 15189044 after the settling interval. Full flash
readback, physical speed, programming and recovery remain unqualified. AutoCal
is absent from ordinary device selection; AL5 live writes remain disabled.

## Static evidence

[`AUTOCAL_TRANSPORT_STATIC.json`](AUTOCAL_TRANSPORT_STATIC.json) records bounded
disassembly of the installed `EFILive_Hapi.exe`, SHA256
`c51bbf4795c2ee0ac54b95114e1d5ae509d7f53d35a160b35115085f444fbcf8`.
The collector rejects other executable hashes. It reads PE sections and invokes
Microsoft dumpbin on explicit address ranges; it never loads the target.
Ghidra opening succeeded, but its requested decompilation timed out after
300 seconds. No pseudocode result or full control-flow coverage is claimed.

The HAPI initializer loads `ftd2xx.dll` and binds `FT_Read` and `FT_Write` to
object slots `0x4C` and `0x50`. Send branch 2 reaches the latter slot through
`0x6EE0B8`; its loop advances by the number of bytes actually written.
This identifies an FTDI transport path, not a J2534 interface.

The native CRC loop at `0x6E2A64`, all 256 table entries at `0xAD2CE4`, and the
send/receive callers establish reflected CRC16 polynomial `0xA001`, initial
value zero, no final XOR, stored little-endian. Coverage is the outer header
and payload. This is separate from VPW CRC and tune checksums.

## Recorded-envelope contract

The implemented profile requires an explicitly supplied HTX direction and a
complete 12-byte header:

- TX: `01 54`, opaque bytes 2 through 9, LE16 payload length, payload, LE16 CRC.
- RX: `01 52`, the same layout, followed by one additional byte after the CRC.
- Prefix, direction and exact length must agree. CRC failures remain available
  as evidence; unknown metadata and trailer values are preserved.
- HAPI also contains an 8-byte-header branch. That profile is unsupported here.
  No automatic stream resynchronization or request/reply pairing is inferred.

`Tools/AL5/autocal_transport.py` reuses the existing HTX/container producers and
retains decoded offsets, source digests and unknown routes. It does not scan
local payloads for byte patterns resembling vehicle messages.
`Apps/PcmLibrary/AutoCalHostFrame.cs` implements the same complete-frame
contract with an explicit direction and defensive copies. It does not require
a fabricated HTX channel for bytes obtained from USB. It has no device, port
or DLL dependencies.

File-only replay of the private read-12 and failed-license-check traces parsed
526 and 108 binary wrappers respectively. All 634 outer CRCs agreed. All 379
RX wrappers ended in `19`; its meaning is unresolved. Twelve and fourteen
routes respectively remain unclassified. Agreement with HTX logging alone does
not establish USB framing, device execution or complete vehicle traffic.

Private source hashes:

- Read 12 HTX: `49e0b14e2e5deb3581baca6c00f8ac29e264e2006d999aa017e4c736c448987f`.
- License-check HTX: `a88c5cd0ec8ac3640c57e6efa3f03151cd1e7af6338444c58b87d9e8ffc423db`.

The shared corpus uses synthetic payloads and explicit malformed cases. It
contains no tune image or device credential. Python's 54 focused replay,
USB analysis and regression tests passed. The standalone C# harness passed
14 shared cases and 146 assertions. A second corpus containing all 24 complete
envelopes from the two actual USB captures passed 262 assertions, with explicit
source direction rather than HTX channel labels. `PcmLibrary` built for its
existing netstandard2.0 target.

```powershell
python -B -m unittest discover -s Tools/AL5 -p test_autocal_transport.py
dotnet run --project Tools/AL5/AutoCalFrameTest.csproj --verbosity quiet
dotnet build Apps/PcmLibrary/PcmLibrary.csproj --no-restore --verbosity quiet
```

## Isolated USB observation

The owner confirmed AutoCal's OBD cable was physically unplugged while USB
remained connected. Windows identified AutoCal V2 as
`USB\VID_0403&PID_E4A3\AC3NCHH5`, FTDI driver `2.12.26.0`, `oem43.inf`.
A fresh elevated, read-only USB inventory selected USBPcap2 address 8. An older
address-2 inventory was not reused after reattachment.

USBPcap was restricted to address 8. EFILive's Control Panel displayed USB
driver `02.12.26`; its Devices page successfully completed one **Read** of
AutoCal settings. No settings were edited or programmed. The temporary
readback view was closed without saving it. No vehicle operation ran.

The owned capture process exited with code zero after a matching stop request
and pipe closure. All recorded handle-cleanup operations succeeded. The saved
PCAP is 6,699,054 bytes, SHA256
`3c5ccaf8d8c661e56104faa9d138282e7f4be5f37fd7df763a66ef175911485f`.
USB traffic continued during the five-second drain window, so a quiet tail was
not achieved. This capture does not establish complete capture at either edge.
The private PCAP, inventory and cleanup receipt are under
`LocalOnly/autocal_usb_setup_20261030/autocal_usb_local_01` and its parent.

The independently collected USB descriptor snapshot identifies the same serial,
VID/PID and address, with bulk IN `81` and OUT `02`, both maximum packet size
64. `Tools/AL5/analyze_autocal_usb.py` binds those raw descriptor bytes to the
source report and removes the two FTDI status bytes **per USB packet**, retaining
their values and exact file offsets. It does not remove them once per URB.
In particular, two 281-byte IN completions each contain five derived packets;
their 271 data bytes form an envelope with a 256-byte payload.

All 11 TX envelopes (171 data bytes) and 11 RX envelopes (733 data bytes) pass
the reconstructed framing and CRC, with no unparsed application bytes. The
PcmLibrary C# decoder independently passes these 22 privately extracted
envelopes. Four IN submissions remain pending at capture end, and eight other
metadata records are retained. Matching the retained data is not a lossless
capture claim. See the compact [USB result](AUTOCAL_USB_LOCAL_20261030.json);
the complete packet ledger and literal payloads remain private.

Independent `FT_CreateDeviceInfoList` / `FT_GetDeviceInfoDetail` calls initially
returned one already-open entry with unavailable identity fields while HAPI
held the device. After the owner exited HAPI, the same probe returned the
expected AutoCal serial, description and VID/PID, with flags zero and device
type 5 (`FT_DEVICE_232R` in the installed header). This is driver enumeration,
not a board-component identification. Neither enumeration opens an FT_HANDLE
or sends an application request.

## Independent model query

The [identity trace](AUTOCAL_IDENTITY_STATIC.json) follows the native `0x8201`
request through the string helper, comparison with `ACV2` / `FSV2`, and a
caller that labels the result `MODEL=`. This established a narrowly bounded
adapter-local query before attempting independent I/O.

With AutoCal's OBD cable physically unplugged and all EFILive processes closed,
a separate Python developer probe opened the exact serial through the pinned
bundled x64 D2XX library. It set bounded read/write timeouts, confirmed an empty
receive queue and sent this request once:

```text
TX: 01 54 01 82 07 00 00 00 00 00 00 00 81 77
RX: 01 52 01 82 00 00 00 00 00 00 05 00 41 43 56 32 00 26 B4 19
```

The reply contains `ACV2\0` and a valid outer CRC. One read returned all 20
bytes; the subsequent queue was empty. The owned device handle closed
successfully and the worker exited with code zero. Twenty offline probe tests
covered partial reads/writes, invalid replies, delayed operations and cleanup
or telemetry failures before this execution. The private one-device probe is
not exposed through PcmHammer's adapter selector.

A simultaneous USBPcap capture independently corroborates the exact request
and response: one 14-byte OUT and one 22-byte IN containing two FTDI status
bytes plus the 20-byte reply. Both outer CRCs pass. The 2,024-byte PCAP has
SHA256 `de99cbc15c0ef51c3977d560d8b2165856fac2ee739e7e5449053de237db3fe0`.
Capture cleanup succeeded and a quiet tail was achieved. Four unsupported
metadata records and the driver's USB control transfers remain recorded;
using no explicit reset API does not mean the driver sent no control traffic.
See the [direct-query evidence](AUTOCAL_DIRECT_MODEL_20261030.json).

This proves independent open/query/read/close for one model request on this
attachment. In that first session AutoCal was not power-cycled between HAPI
and the probe. The later model-only power-cycle check is described below.
Header metadata, request/reply correlation and general transport readiness
remain unresolved. The host's
use of trailing `0x19` as an FTDI event character is statically established;
its complete firmware semantics are not.

## Model query after reported USB power cycle

The owner confirmed the requested five-second USB disconnection and
reconnection, with OBD unplugged and EFILive closed. Before opening the
adapter, Windows again reported the exact AutoCal PnP identity as healthy;
no EFILive, HAPI or USBPcap process was present. The reviewed probe and its
source dependencies were byte-identical to those used for the first query.

The same fixed request succeeded on the new attachment: one 14-byte write,
one 20-byte read, and the exact same `ACV2\0` reply and valid outer CRC. Both
queue checks were empty, `FT_Close` succeeded and the worker exited with code
zero. The recorded session lasted 0.469 seconds. See the separate
[power-cycle repeat evidence](AUTOCAL_COLD_MODEL_20261030.json).

This qualifies the model query after the user-reported power cycle without
reopening EFILive. No USBPcap recording was made for this repeat; its bytes
come from the D2XX probe journal. Physical power removal was user-attested,
and persistent adapter settings were not reset or inspected. General
initialization, VPW messaging, programming and recovery remain unqualified.

## C# test using PcmLibrary

The standalone [C# model test](AUTOCAL_MODEL_PROBE.md) now references and
loads the actual PcmLibrary project build. Its isolated AutoCal query passed
with the same request/reply as the Python tests, a valid CRC, empty receive
queues and successful device/library cleanup. The project build and offline
failure checks also passed. See its [evidence](AUTOCAL_CSHARP_MODEL_20261030.json).

This developer CLI exposes one fixed model query. It does not add an AutoCal
entry to PcmHammer's adapter selector or implement a general vehicle port.

## Command 0x8A00: offline field projection

The [focused native trace](AUTOCAL_VPW_TRANSPORT_STATIC.json) now follows
HAPI's send arguments, receive context, length guard and error-envelope path
through twelve bounded windows in the same pinned executable. The layouts
are different in the two directions:

- TX command `0x8A00` occupies bytes 2-3. Byte 4 is the low byte of HAPI's
  object selector, byte 5 is written as zero, and bytes 6-9 carry a caller
  metadata DWORD unchanged. The caller's payload is copied at byte 12.
- Normal RX interpretation requires the requested-command context. For
  `0x8A00`, bytes 2-5 are one returned metadata DWORD, not an echoed command
  or a receive route. Bytes 6-9 remain opaque. The payload is copied unchanged.
- RX bytes `00 FF` at offsets 2-3 select a separate host error envelope.
  Its payload begins with an echoed command and a separate error-status word.
  An echo mismatch is an error; this payload must never be treated as VPW data.
- The inspected receive consumer rejects a positive payload length above
  `0xC000`. This does not establish the same limit for transmitting.

Metadata value `0x10` has no proven ACK, success or speed meaning. Native VM
callbacks keep returned metadata separate from exception status. A nearby TX
in an HTX file does not establish the context or pair a particular RX to it.
Historical `route_*` fields in the earlier replay reports retain their raw
byte meaning; their RX candidate groups are not a live dispatch rule.

`Apps/PcmLibrary/AutoCalVpwEnvelope.cs` projects these fields only with an
explicit `ExplicitVpwRequest8A00Context`. Missing or unsupported context,
invalid outer CRC, wrong TX command, oversized RX payload and malformed or
mismatched host errors retain raw evidence but expose no accepted bus payload.
Normal metadata remains a raw number; error status is exposed only when the
echoed command matches. Array properties return defensive copies. There is no
stream reader, request matching, device opening, transmit method or adapter
selector entry. An incorrectly supplied RX context cannot be detected from
those bytes alone; this API is not a bus-message identification oracle.

The [saved-trace inventory](AUTOCAL_VPW_TRACE_20261030.json) retains every
binary wrapper's order, decoded offset, header, payload digest and outer CRC
from read 12 and the failed-license-check W trace. It records small setup
payloads separately and never searches local transform data for bus messages.
There are 162 and 26 TX `0x8A00` envelopes respectively. Every one carries
`10 00 00 00` in TX bytes 6-9, including before and after the recorded `A1`
message. That observation cannot identify physical bus speed.

The saved read includes a six-byte `0x8604` command before its first bus
candidate. The W log reaches its first bus candidate before its first recorded
`0x8604`, so these transcripts do not establish a complete independent
initialization recipe. The meanings and requirements of `0x8603`, `0x8604`,
filters, speed changes and completion flags still need evidence. The W file
was a failed license check, not a successful flash or recovery demonstration.

The comparison to the prior GT report reproduces 390 matching occurrences
out of 392 expected messages, with two missing and five extra GT messages.
The TX/RX payload digest sets are disjoint for this particular trace, so the
132 TX and 258 RX matches are not double-counted. For other files, shared
digests are explicit and per-channel upper bounds cannot be summed. These
counts do not identify physical senders. They corroborate unchanged payload
bytes for those matches after the prior GT parser's declared trailing-CRC
removal, not a universal CRC policy or lossless monitoring.

The actual PcmLibrary project built successfully with three existing CS1998
warnings in `Vehicle.cs` and `Devices/MockDevice.cs`. The new C# harness passed
55 boundary assertions, then 500 saved envelopes (188 TX, 312 RX), for 5,248
assertions including the boundary cases. RX context in that private corpus is
explicitly assumed for field testing, not proven by pairing. All 65 focused
Python framing, replay, comparison and collector regressions passed. No
adapter was opened or queried during this work. Source and artifact digests are
recorded in the [offline test receipt](AUTOCAL_VPW_PROJECTION_TEST_20261030.json).

```powershell
python -B -m unittest discover -s Tools/AL5 -p test_autocal_vpw_trace.py
python -B -m unittest discover -s Tools/AL5 -p test_inspect_autocal_vpw_transport.py
dotnet run --project Tools/AL5/AutoCalVpwEnvelopeTest.csproj --verbosity quiet
```

## Bus setup producers and transfer completion

The [VM setup reconstruction](AUTOCAL_VM_SETUP_20261030.json) now binds the
installed E54 read object to the exact transform requests and recorded replies
in read 12. All sixteen transform envelopes pass outer CRC, every source chunk
matches the object, and the reconstructed code/data pass the native buffer CRC
(`D9CB`). Its 1,045 structurally grouped instructions include four opcode `99`
setup sites, two opcode `93` cleanup sites and one opcode `90` selector site.
This is saved-reply reconstruction, not independent firmware decryption or VM
execution. The existing AL5 object admission rules were not broadened.

The native path connects opcode `99` through VM helper `4074DC`, callback
slot `4398CC`, and Scan callback `BB0A14`. The
[Scan callback trace](AUTOCAL_SETUP_CALLBACK_STATIC.json) establishes:

- For a positive second argument, command `8603` contains two little-endian
  words: the argument divided by 1000 and its remainder. The arithmetic is
  established; firmware units and effect remain unknown.
- Command `8604` contains the first argument's low byte, the third argument's
  low byte, and the fourth argument as a little-endian DWORD.
- VM arguments `(1, 1500, 0, 16)` reproduce recorded `8603: 01 00 F4 01` and
  `8604: 01 00 10 00 00 00`. Four zero arguments reproduce the recorded
  six-zero-byte `8604`. These forms are observations, not a configuration recipe.
- The setup callback omits optional exception/metadata outputs and does not
  check returned status. Emitting both commands therefore does not establish
  successful configuration.

The script's initial code descriptor at `2142` contains 1500, and its copy at
`283C` assigns 16 through special reference `FF04`. The native resolver maps
that reference to descriptor `427652`. These facts explain the recorded form,
but unmodeled calls and runtime changes prevent claiming complete dynamic
argument provenance or a meaning for flag `0x10`.

Opcode `90` also requires care. Its Scan callback conditionally sends `8800`
only when receiver field `+7A` is 3, and updates a host cache only after a
nonnegative result. The VM nevertheless writes its own routing globals after
that callback without checking the result. A VM route value cannot establish
that the adapter changed protocol, bus state or physical speed.

Opcode `93` reaches helper `407350`, which packs four resolved low bytes into
command `8B01` through the common callback. It does not check returned status.
The read script's forms `(0,1,0,0)` and `(1,1,0,0)` match TX records 1186 and
1188, after the final data response at 1181. This establishes cleanup ordering
in that capture; it does not identify firmware filter or speed effects.

A separate [HAPI initialization trace](AUTOCAL_SETUP_NATIVE_STATIC.json)
shows a one-byte `8604` compatibility query, optional short-header fallback,
then `8800`. Successful fallback retains the short-header mode. That path is
distinct from the six-byte script command, and the current long-header decoder
does not implement that fallback. The trace also identifies explicit receive
and transmit queue purge calls and logical timeout caching. Neither is proof
of a quiet physical bus or safe state recovery.

The [transfer completion trace](AUTOCAL_COMPLETION_STATIC.json) identifies a
conditional weakness in the inspected FTDI helpers: their final count guard
compares remaining bytes with cumulative transferred bytes. Under a supplied
zero-status partial return, the guard can pass while bytes remain. The shown
HAPI callers do not independently verify the output count. This is a static
conditional path demonstrated with synthetic counts, not an observed adapter
failure and not an explanation proven for the GT's missing acknowledgments.

For positive-byte requests, logical timeouts give a maximum driver-call budget
of `ceil(read_timeout/250)` or `ceil(write_timeout/1000)`, stopping earlier on
full transfer. The receive path scans up to fifty candidates and can drain
some mismatched messages. These bounds are not a single elapsed deadline,
lossless resynchronization, or controller acknowledgment. An independent
backend must account for exact bytes and handle ambiguous delivery explicitly;
these findings do not authorize copying host retries into a flash session.

Real-source collection passed for 17 HAPI initialization windows, 11 Scan
callback windows, 18 completion windows and nine VM bridge windows. The focused
Python suite passed 74 tests, including malformed/reordered transform records,
source mismatch, scalar narrowing and partial transfer counts. The new tools
are file-only; PcmLibrary's active model-only probe, adapter selection and
vehicle paths were not changed. No adapter or vehicle command ran.

```powershell
python -B -m unittest discover -s Tools/AL5 -p test_autocal_vm_setup.py
python -B -m unittest discover -s Tools/AL5 -p test_autocal_completion.py
```

## Setup responses and the speed-request path

The [setup-response trace](AUTOCAL_SETUP_RESPONSES_STATIC.json) follows ordinary
replies for explicit commands `8603`, `8604`, `8800` and `8B01`. Their command
echo must match the caller's requested command. Header bytes 4-9 remain opaque.
The common callback returns received payload **length**, including zero for an
empty normal reply; it does not return a decoded firmware-success byte. The
saved read and failed-license W traces contain thirteen empty setup replies
and four one-byte `01` cleanup replies. Neither contains an `8800` envelope.

`Apps/PcmLibrary/AutoCalSetupResponse.cs` now projects that contract without
opening a device. It requires explicit supported command context and a complete
CRC-valid RX envelope, retains opaque bytes, and distinguishes command mismatch,
malformed errors and matching command errors. A `00 FF` error marker remains an
error even when its status is zero. No accepted envelope establishes physical
configuration, speed, or transaction pairing.

Two static host caveats matter for future integration. On a zero-length reply,
Scan's IPC helper skips resizing its request array, so an optional copy can
retain request bytes while the callback returns zero. A hypothetical error
reply with status zero can also collide with HAPI's zero-valued IPC success
result. Neither behavior has been observed in a hardware test. The independent
projector uses the complete received extent and rejects error markers regardless
of status, rather than reproducing these ambiguities.

The [E54 read VM speed trace](AUTOCAL_SPEED_VM_STATIC.json) narrows the path:

- A script enable descriptor and a `0x10` mask on caller-supplied VM step state
  gate entry to the helper. This is a gate for attempting the sequence, not
  proof that AutoCal has changed speed.
- The helper sends `6C FE F0 A0`, then invokes a bounded receive/drain helper.
  That helper requests up to twenty receives with a callback argument of 250,
  stopping on its `0x80` flag. It does not inspect the `E0 AA` response bytes
  as a speed acknowledgement.
- It sends `6C FE F0 A1`, requests `KERNEL32!Sleep(1000)`, then opcode `64`.
  The latter reaches callback selector `0A` and, on the traced FTDI backend,
  queue purge with mask 3 (receive and transmit). It is not a separate adapter
  speed-setting command.

These are bounded static paths from the pinned reconstructed E54 read object;
full VM execution and dynamic reachability are not established. They do not
establish the AL5 programming script's behavior.

The [saved timeline](AUTOCAL_SPEED_TRACE_20261030.json) independently preserves
record order, offsets, raw saved timestamps, wrapper CRCs and payload digests.
The A0-to-A1 logged intervals are about 278 ms in read 12 and 267 ms in the
failed-license W trace. A1-to-first-mode-34 intervals are about 1,015 and
1,014 ms. There is no adapter-local TX between A0 and A1, or between A1 and
that next request. These are host-log intervals, not measured wire timings.
Unchanged TX metadata `0x10` cannot identify physical speed. The absence of an
explicit speed command suggests firmware or pre-existing state may participate,
but that mechanism remains unresolved.

Cleanup still consists of the recorded zero-form `8604` and two `8B01` forms;
their firmware effects do not yet establish a return to 1x. PcmHammer's device
API expects `SetVpwSpeedInternal` to establish the selected adapter speed before
updating its speed cache. The traced host sequence cannot yet supply that
implementation. At that tracing checkpoint, no AutoCal device backend or live
send path had been added.

The actual PcmLibrary build passed with the same three pre-existing CS1998
warnings. The setup-response harness passed 144 boundary assertions and all
17 saved setup replies, for 284 assertions in the saved-corpus run. All 89
focused Python tests passed; 28 current source/helper digests matched the
reports. Its corpus chooses command context explicitly for field testing; it does not infer a
transaction match. Source digests and validation are recorded in the
[offline test receipt](AUTOCAL_SETUP_SPEED_TEST_20261030.json).

```powershell
dotnet run --project Tools/AL5/AutoCalSetupResponseTest.csproj --verbosity quiet
python -B -m unittest discover -s Tools/AL5 -p test_autocal_speed_trace.py
python -B -m unittest discover -s Tools/AL5 -p test_autocal_speed_vm.py
```

## Polling configuration, cleanup exits and firmware containers

The [native configuration trace](AUTOCAL_SPEED_CONFIGURATION_STATIC.json)
identifies another setup producer, Scan `BB497C`. Two callers pass the named
`TProperties.Logging_PollTime` field as the value split into the `8603` words.
RTTI, the property setter, construction and the global object reference agree
on that field. This establishes the host source of the value. Firmware timer
units and any effect on VPW timing remain unknown.

This producer uses a signed 32-bit polling value and narrows its positive
quotient/remainder to 16 bits. It differs from the previously traced VM
producer's argument widths and range guard. Its offline model therefore stays
separate. Its observed `8604` forms include mode 1 with polling, mode 6 with
zero remaining arguments, and all zeros; they cannot yet be assigned 1x/4x
meanings. The receiver slots used by the two producers can refer to the same
receiver object.

The [cleanup trace](AUTOCAL_CLEANUP_VM_STATIC.json) distinguishes normal
completion, first script error, repeated error, direct host error entry and
host cancellation. Under the modeled ordinary-call assumptions:

- Normal completion clears the error before common cleanup. A first script
  error prepares an error status; a repeated script error can return its cached
  status without running common cleanup again. Pending VM frames are not
  presumed unwound.
- The `3C55` exchange helper returns on a matching negative response as well as
  a matching positive service/PID. The saved read has a timeout, another `3C55`
  attempt and negative `7F 3C 55 31`, followed by the later cleanup messages.
  Proceeding past this exchange does not establish successful controller reset.
- Host cancellation can bypass remaining script steps, assign status `0508`,
  and request the zero-form `8604` directly before VM teardown.
- Opcode `59` writes the value exposed by `vmGetCountdown` to the host UI.
  The E54 read uses 15; the compared AL5 write structure uses 30. The countdown
  value is not an adapter speed command.

Several helper instruction hashes match the existing AL5 structural report.
That comparison does not revalidate the AL5 code pool, dynamic execution,
physical return to 1x, or recovery from interrupted programming.

Four installed V2 `.efw` artifacts now have a
[container inventory](AUTOCAL_FIRMWARE_CONTAINER_STATIC.json). Each program
file has three positive LE32-length regions; each boot file has one. Exact
framing covers every byte. The bytes remain opaque: measured entropy, common
prefixes and periodic tails do not establish a codec or processor architecture.
Installed package names do not establish the firmware running on an adapter.

The [native firmware loader](AUTOCAL_FIRMWARE_LOADER_STATIC.json) independently
binds program-file handling to `TFileStream` and `kernel32!ReadFile`. It reads
and concatenates a first region bounded by `0x20000`, an optional `0x8000`
middle region, and a final region bounded by `0x40000`. The later chunk routine
copies up to 256 source bytes unchanged into its exchange buffer. These stages
expose no plaintext instruction decoder. Later transport or device-side
transformation remains unknown.

The new program-layout model emits offsets, lengths and digests only. It
requires complete framing and EOF, rejects missing regions and oversized
lengths, and does not emulate the native code's unchecked stream-read counts.
No firmware image is exported and no update path is implemented. REA's firmware
signature provider is unavailable on this Windows session; the work uses
bounded file parsing and pinned native disassembly, with that limitation kept
explicit.

All 50 focused offline tests passed. Real collection covered 38 new native
windows, 111 selected cleanup nodes and four installed firmware artifacts.
The [validation receipt](AUTOCAL_CONFIGURATION_CLEANUP_TEST_20261030.json)
records source hashes and scope. PcmLibrary, its model-only USB probe, device
selection, the working reader and live-write gates were not changed.

```powershell
python -B -m unittest discover -s Tools/AL5 -p test_autocal_speed_configuration.py
python -B -m unittest discover -s Tools/AL5 -p test_autocal_cleanup_vm.py
python -B -m unittest discover -s Tools/AL5 -p test_autocal_firmware_container.py
python -B -m unittest discover -s Tools/AL5 -p test_autocal_firmware_loader.py
```

## Experimental backend and isolated setup execution

`AutoCalChannel` now owns exact byte framing, serialized exchanges and bounded
I/O. Successful partial writes continue only their remaining suffix. Ambiguous
transfers, malformed envelopes and mismatched context stop the session; they
are not replayed or silently purged. Pending native work and failed close
operations retain their owner until cleanup succeeds.

`AutoCalDevice` implements PcmHammer's existing message and timeout interface.
Its current observed limits are 1,772 outgoing and 4,108 incoming VPW-message
bytes. The ordinary writer still limits flash data blocks to 1,024 bytes plus
12 bytes of framing. These are selected bounds, not established firmware
maxima. `SendMessage` success means exact host submission; subsequent controller
replies and verification determine operation success. The backend refuses 4x
transitions, and its initial Standard speed cache does not prove physical 1x.

The Windows transport uses the pinned bundled x64 D2XX DLL and explicit serial
selection. It is deliberately separate from serial auto-detection. The
standalone `AutoCalBackendProbe --usb-setup` mode exposes only an exact
model/setup/cleanup sequence while OBD is physically unplugged. A separate fixed
E54 identity profile admits one OS-ID query for isolated-bench qualification;
its later successful execution is documented separately below. Neither accepts
arbitrary VPW commands. The factory and ordinary CLI do not expose AutoCal.

The [USB setup result](AUTOCAL_BACKEND_USB_SETUP_20261030.json) records the first
actual execution through this backend. An independent audit of its saved
journal found eight complete TX and eight complete RX envelopes: 139 bytes
submitted, 128 received, all sixteen outer CRCs valid, and every command echo
matching in order. There were no short transfers or host replays. The model
reply was `ACV2\0`; `8800` returned payload `00`; the two `8B01` replies returned
`01`; the other setup replies were empty. These payloads are retained without
assigning firmware-success meanings.

The last journal event at 853 ms reports empty host and adapter receive queues.
The result reports transport disposal, zero retained native owners, and no
channel or cleanup exception. The evidence comes from the D2XX journal; this
session has no independently audited USB packet or waveform recording.
Private raw files remain under `LocalOnly/AutoCalBackendProbe/usb_setup_01.json`
and its `.journal.jsonl` sibling. The public result pins both files, the tested
source and the exact probe, PcmLibrary and native-library builds.

The historical raw receipt's `vehicle_transmissions = 0` means **zero submitted
host `8A00` VPW-payload commands**. It does not establish zero autonomous adapter
pulses or other physical effects of setup. This experiment does not establish
bus initialization, filters, 1x/4x behavior, ECU communication or recovery.

Offline tests use scripted in-memory transports. They exercise fragmentation,
coalescing, errors, deadlines, cancellation, queue handling and retained
cleanup. The device suite includes 96 program payloads and 98 synthetic replies
(two erase replies plus 96 program replies); those are test fixtures, not a
hardware flash transcript. A separate 26-case production-writer suite uses a
synthetic image and scripted Device. It checks current-result CRC success,
verification after the fifth allowed write pass, failure/cancellation handling,
and E54 uncertain-erase preservation without another erase or kernel reset.
`WriteManager` now propagates the writer's Boolean result.

An independent repeat exposed an idle-receive deadline race: expiration between
the receive loop and its next I/O guard incorrectly faulted an empty idle
receive. The correction keeps idle expiration separate from partial bytes or
an outstanding native operation. Fresh offline runs pass 246 channel assertions,
all nine device scenarios with 349 assertions, and 14 frame cases with 146
assertions. Both the earlier failure and corrected repeat remain pinned in the
public result. The successful eight-command hardware setup above retains its
original source/build hashes; it does not physically qualify the later build.

The [fixed probe guide](../../Tools/AL5/AutoCalBackendProbe/README.md) describes
the bounded ordinary identity experiment. Its additional offline harness passes
84 assertions covering immutable command profiles, complete OS-ID validation,
partial-write continuation and replay rejection. Both observed response extents
run through the production ordinary-profile Device and Channel. This harness
does not open native USB or a controller.

## Independent E54 identity exchange

The [E54 identity result](AUTOCAL_E54_IDENTITY_20261030.json) records a successful
ordinary query on the isolated spare E54/LB7 using AutoCal directly through the
production backend. The probe used source commit `47e7547`; all nine recorded
source hashes match that commit's blobs. This was a separate execution from
the USB-only setup above, with its own source, assembly and evidence pins.

The saved journal contains eight complete TX and eight complete RX envelopes:
140 bytes submitted and 139 received, all sixteen outer CRCs valid. The exact
planned order matches. Seven ordinary replies echo their command; the remaining
reply is interpreted in explicit `8A00` receive context. There are no short
transfers or host replays in this journal.

Exactly one VPW-payload request was submitted:

```text
TX payload: 6C 10 F0 3C 0A
RX payload: 6C F0 10 7C 0A 00 E7 C4 34 44 4E
```

Bytes `00 E7 C4 34` decode to OS `15189044`. The trailing `44 4E`, receive
header's remaining opaque bytes and returned metadata `0x10` are preserved;
they do not identify physical speed or firmware execution state. The host
journal places the reply 99 ms after the write event, which is not a wire-time
measurement. This establishes one matching identity exchange on this bench
attachment; it does not qualify arbitrary VPW traffic or programming.

Recorded cleanup completed. At the final journal event, 891 ms after its clock
started, both receive queues were empty. The result reports native transport
disposal, zero retained native owners, and no channel or cleanup exception.
Raw files remain under `LocalOnly/AutoCalBackendProbe/e54_osid_01.json` and its
`.journal.jsonl` sibling. Their hashes and the exact tested builds are retained
in the public result. No independent USBPcap or scope audit is claimed for this
session, and cleanup does not prove physical bus OFF or return to 1x.

No unlock, kernel upload, full image read, erase, program, verification or
interrupted-write recovery operation ran in this fixed profile. The normal
AutoCal factory entry and AL5 live writes remain disabled.

## Stock RAM-copy acknowledgement gap

The [saved-evidence inventory](AUTOCAL_STOCK_RAM_COPY_ACK_GAP_20261030.json)
examined all 13 local E54 HTX files and seven GT operation logs, plus their two
empty stderr logs. Every HTX RAM upload uses a single `36 80` execute packet;
none contains a stock-ROM `36 00` RAM copy. The GT logs contain six RAM execute
uploads, 96 flash copies and 96 test writes. Flash-copy replies come from the
running kernel and cannot establish the stock-ROM RAM-copy response contract.
The saved execute reply is `6C F0 10 76 80 78`. Its last byte is not the ordinary
J1850 CRC of the preceding five bytes: that CRC is `E2`; the CRC of all six
bytes is `02`. The meaning of `78` remains unknown.

At the existing AutoCal transmit cap, PcmHammer divides the pinned 2,027-byte
kernel into a 267-byte RAM copy at `FF97E0`, then a 1,760-byte execute packet at
`FF9100`. A reply with an opaque final byte cannot prove that the first copy
succeeded before execution. The bounded COPY-only experiment described below
has now recorded one such reply, without executing the kernel or verifying RAM
contents. At that checkpoint full kernel execution remained disabled, and the
COPY-only profile required a bench power cycle. The later pinned-kernel result
below is separate evidence. The historical inventory remains unchanged: it pins
its earlier private inputs and script and contains no kernel payload.

## Independent COPY-only RAM observation

The [COPY-only result](AUTOCAL_E54_RAM_COPY_20261030.json) records a later
isolated E54 bench session from source commit `92eb11b`. All twelve recorded
source hashes match that commit. After the fixed identity, suppression,
seed/key and upload-permission sequence, the probe submitted one mode `36 00`
packet containing the pinned kernel's final 267 bytes at `FF97E0..FF98EA`.
The submitted payload exactly matches file offset 1,760, and its block checksum
passes. These checks establish the outgoing bytes, not their contents in RAM.

The corresponding reply was:

```text
6C F0 10 76 00 78
```

The service/copy fields match the request. The final `78` remains opaque;
there was no RAM readback or CRC. This is a successful observation of the copy
reply, with `RamCopyBytesVerified = false`. The policy's recorded next phase
`RamExecute` does not mean execution occurred: mode `36 80` submissions were
zero, and no kernel-version query was sent.

The journal contains twelve complete application TX and ten RX envelopes
(496 and 197 bytes respectively), all twenty-two outer CRCs valid. Eight TX
and six RX carry VPW payloads. One native read returned zero bytes before the
copy reply arrived; there was no copy replay or short write. The copy reply
arrived 233 ms after its host write event, with physical speed unmeasured.

The probe stopped after the reply. It sent no flash read, CRC, erase or program
request, no DTC clear, controller exit, speed change, or later protocol cleanup.
At the last event, 1,338 ms into the journal, both receive queues were empty.
The native owner reports successful disposal and zero retained owners. Raw
bytes remain in `LocalOnly/AutoCalBackendProbe/e54_ram_copy_01.json` and its
`.journal.jsonl` sibling; the public result pins them and the tested build.
This is a D2XX journal audit, not an independent electrical capture.

The COPY-only session ended with a bench power cycle required. The subsequent
[post-reset identity check](AUTOCAL_E54_POST_COPY_RESET_20261030.json) is separate
evidence, described below; the original COPY-only receipt remains unchanged.
Full kernel execution was disabled at that COPY-only checkpoint. Programming
and AL5 live writes remain disabled; the subsequent kernel-info experiment is
recorded separately below.

## Ordinary identity after the reported power cycle

The owner reported power-cycling both the bench and AutoCal, then returning the
isolated E54 bench to ignition ON at 13.8 V with EFILive closed. Those physical
steps and voltage are user-attested. A separate fixed ordinary identity probe
then returned OS `15189044`; see the
[post-copy reset result](AUTOCAL_E54_POST_COPY_RESET_20261030.json).

The audit found eight exact planned TX and eight RX envelopes, 140 and 139 bytes
respectively, with all sixteen outer CRCs valid. The only VPW request was
`6C 10 F0 3C 0A`; its reply was `6C F0 10 7C 0A 00 E7 C4 34 44 4E`. No replay
or short transfer occurred. All twelve recorded source hashes match commit
`42cf710`; source, binary and private raw-file digests are in the result.

Recorded cleanup completed. At the final 915 ms journal event the receive
queues were empty, and the native owner reports successful disposal with zero
retained owners and no error. This establishes an ordinary matching identity
exchange after the reported reset. It does not verify the earlier copied RAM
bytes, full kernel execution, flash programming or interrupted-flash recovery.
No such operation ran in this identity session, and physical speed remains
unmeasured. Earlier receipts retain their original scope and hashes.

## Independent pinned RAM-kernel execution

The [kernel execution result](AUTOCAL_E54_KERNEL_EXECUTION_20261030.json) records
a successful fixed `e54-kernel-info` session from commit `6891836`. All twelve
recorded source hashes match that commit. The outgoing 267-byte COPY and
1,760-byte EXECUTE fragments exactly match the pinned 2,027-byte kernel, with
valid block checksums and destinations `FF97E0` and `FF9100`. Each was submitted
once, with its expected reply required before the next step.

The observed sequence then established:

- COPY reply `6C F0 10 76 00 78`, followed by EXECUTE reply
  `6C F0 10 76 80 78`.
- Exact kernel-version reply `6C F0 10 7D 00 6A B1 78 EC 36`, matching the
  pinned expected value `458244025398`.
- Exit acknowledgment `6C F0 10 60`, then ordinary OS `15189044`. The final
  identity request occurred 10,018 ms after the exit reply, satisfying the
  configured 10-second settling margin.

The exact known version is evidence that the relevant uploaded kernel path
executed. The opaque `78` alone was not treated as proof. No independent RAM
readback verified every uploaded byte, and no flash image read, CRC query,
erase, program, DTC clear or speed change ran in this profile.

The audit found nineteen application TX and seventeen RX envelopes (2,394 and
335 bytes), all thirty-six outer CRCs valid. Twelve TX and ten RX carried VPW
payloads. Fourteen native reads returned zero bytes while waiting: two before
the COPY reply and twelve before the EXECUTE reply. They did not cause an
upload replay or a short write; both replies arrived and the bounded sequence
completed. These are host-journal observations, not electrical timing or
lossless-monitoring claims.

Recorded adapter cleanup succeeded. At the last journal event, 13,630 ms into
the session, the receive queues were empty; the native owner reports disposal,
zero retained owners and no error. The result required no additional bench
power cycle. Private raw files are
`LocalOnly/AutoCalBackendProbe/e54_kernel_info_01.json` and its `.journal.jsonl`
sibling; the public receipt pins them, the source, both runtime assemblies and
the kernel asset. Prior receipts retain their original scope and hashes.

This qualifies the observed version/exit/identity sequence for this pinned
kernel on this bench attachment. It does not establish full flash readback,
other kernels, physical 4x behavior, programming or interrupted-flash recovery.

## First full-read attempt: no data reply

The [failed full-read audit](AUTOCAL_E54_FULL_READ_BLOCKED_20261030.json)
records the first physical `e54-read-baseline` attempt from commit `19ff0fb`.
All 22 recorded source hashes match that commit, and both runtime assembly
hashes match the archived build under `LocalOnly/AutoCalBackendProbe/builds/19ff0fb`.
Adapter setup, initial OS `15189044`,
both pinned RAM uploads, the exact kernel version, and flash ID `00894471`
(Intel 28F400B) passed. This run did **not** complete a flash image read.

At journal time 3,130 ms, the probe submitted one request for 4,096 bytes at
address zero: `6D 10 F0 35 01 10 00 00 00 00`. No bytes were subsequently
delivered by native D2XX reads. The journal records 475 zero-byte native read
completions after that request, through 53,189 ms. The five logical receive
windows each used the configured 10-second timeout. When the shared reader
attempted to resend the request, the policy rejected it before host submission.
There was exactly one submitted data request and no further protocol traffic.

The audit independently reconstructed eighteen TX and thirteen RX application
envelopes (2,380 and 267 bytes), with all 31 outer CRCs valid and no short write.
Fourteen TX and nine RX envelopes carried VPW payloads. The entire run contains
502 native read completions, including 489 zero-byte reads; those native calls
must not be confused with the five logical receive timeouts. Both outgoing RAM
fragments match the pinned kernel and have valid block checksums.

Zero data blocks and zero controller CRC ranges completed. The reserved
`.readback.bin` file is empty, and no image hash or comparison to the GT baseline
was obtained. The receipt's top-level `received_vpw_frames = 0` and null identity
fields are success-only defaults: the journal and nested `kernel_result` retain
the nine actual replies and the successful initial identity. They do not mean
the adapter returned nothing during the whole session.

No exit/reset, post-exit identity, DTC clear, speed change, flash erase/program
or recorded adapter cleanup followed the failure. Native transport disposal
completed with zero retained owners and no channel or cleanup fault. The run
ended requiring a bench power cycle; a later reset or identity result must be
recorded separately. Physical speed remains unmeasured.

The repeatable [saved-read comparison](AUTOCAL_READ_GAP_20261030.json) finds
that the failed first request matches EFILive read 12 record 158 byte for byte,
including the outer wrapper and CRC. The saved read returned short acknowledgements
and data for all 128 requests. Its earlier adapter state and different kernel
remain relevant differences; an identical request alone does not identify why
the independent attempt returned no data.

This establishes a failure at the first data exchange, not its cause. The D2XX
journal cannot distinguish missing kernel transmission from adapter reception,
setup, filtering, timing or framing behavior. No independent bus capture belongs
to this run. The earlier successful kernel version/exit session remains separate
evidence; the independent AutoCal full-read path is still unqualified.

## Prefix-read attempt: no data reply

The separate `--e54-read-prefix` profile limits the data exchange to one
64-byte request at address zero. It checks the same kernel and flash identity,
then requires an exact transfer checksum and the pinned baseline-prefix digest
before allowing exit. It does not query controller CRCs or verify the full
image. Its receipt distinguishes `baseline-prefix` from `full-image` coverage.

The [first prefix-read audit](AUTOCAL_E54_PREFIX_READ_BLOCKED_20261030.json)
records a physical attempt from commit `d138947`. All 22 recorded source hashes
match that commit; runtime hashes match the archived build under
`LocalOnly/AutoCalBackendProbe/builds/d138947` at audit.
Setup, initial OS identity, the exact RAM-kernel version and flash identity
passed again. The request `6D 10 F0 35 01 00 40 00 00 00` was submitted once at
3,150 ms and its host write completed at 3,151 ms. No further host command was
submitted, and no response bytes were delivered after it.

The journal has eighteen TX and thirteen RX host envelopes, all 31 outer CRCs
valid, containing fourteen VPW requests and nine replies. Of 312 native read
completions, 299 returned zero bytes. There were 285 empty native reads after
the data request, through 33,193 ms: an observed interval of 30,043 ms. Two
logical receive windows ended normally without a payload. During the third
10-second window, the channel deadline expired while a native read was still
pending, and the session stopped conservatively at 33,214 ms.

The retained pending transfer subsequently completed with zero bytes and no
error. Its 4,096-byte host buffer is unrelated to the requested 64 flash bytes.
The native owner closed successfully with zero retained owners. The deadline
fault explains the stop boundary; it does not locate the missing data, which
had already been absent for about thirty seconds. Unlike the earlier full-read
attempt, this run did not reach five ordinary timeouts or an attempted resend.

The reserved prefix file is empty. No prefix digest, controller CRC or full-image
comparison passed, and no exit/reset, post-exit identity, speed change, flash
erase/program or adapter protocol cleanup followed the failure. A later bench
reset is separate evidence. Both read profiles remain unqualified; neither
host-only capture establishes whether the kernel transmitted the missing reply
or whether the adapter, setup, filtering or bus path prevented its delivery.

## Paired GT observation locates the missing prefix response

The [paired capture audit](AUTOCAL_E54_GT_PREFIX_20261030.json) compares a new
AutoCal prefix run with simultaneous OBDX Pro GT capture. The GT was checked
in LISTEN ONLY at the 1x setting with exact source `10`, CRC validation enabled,
and no vehicle-send command path. Its raw serial replay contains nine ECM
responses matching AutoCal's responses in order, followed by the missing data
response: 77 physical bytes, header `6D F0 10 36 01 00 40 00 00 00`, and 64 bytes
matching the pinned baseline prefix. Both the VPW CRC and block checksum pass.
The complete data body stays private.

AutoCal's corresponding request was followed by 477 native read completions,
all returning zero bytes, across 50,053 ms. It exhausted the five receive
windows without retry, exit or flash operation and closed with no channel or
cleanup fault and zero retained owners. The GT completed its bounded capture,
verified network OFF and restored all nine saved settings. All 832 GT network
frames pass VPW CRC checks; seven frames before the capture-ready marker are
excluded from the qualified comparison context. No losslessness or electrical
non-interference claim follows from those observations.

The ECM therefore emitted the expected prefix response, while AutoCal did not
deliver it under the tested configuration. Firmware reception, configuration
and host delivery remain possible locations within AutoCal; the application
parser cannot discard data that the native reads never returned.

All twelve saved EFILive reads include `8603{0100F401}` and
`8604{010010000000}` before upload, then the six-zero `8604` before data reads.
The independent ordinary profile omitted the middle pair. A separate bounded
`--e54-read-prefix-recorded-setup` experiment now reproduces that lifecycle
around the same identity, pinned kernel and 64-byte read. It adds three exact
adapter commands and retains all flash-write and speed-change blocks. Its
offline tests establish ordering and failure behavior; physical receive effects
remain untested. `8B01` occurs only in saved cleanup and is not assigned an
unsupported filter-enable meaning.

## Remaining integration work

The developer probe now has a separate fixed baseline-read profile. It reuses
the production reader after verified kernel execution and checks 128 sequential
4,096-byte blocks, the pinned 512 KiB GT baseline hash, and seven controller CRC
ranges. The normal reader retains its existing upload and cleanup ownership;
the new running-kernel entry point leaves those responsibilities with its caller.
The AutoCal coordinator allows successful exit only after verified readback;
any failure stops without another RAM upload or controller reset. Offline tests
cover corrupt blocks, mismatched baseline/CRCs, wrong flash identity and
cancellation. Its first physical attempt reached the known kernel and flash ID
but returned no data for the first block, as recorded above. Offline passing
tests do not qualify the failed physical read path. The separate 64-byte prefix
profile also reached the kernel and flash identity but returned no data, as
recorded above; reducing the request length alone did not resolve the gap.

The bounded setup, ordinary identity, COPY-only observation, post-reset identity
and pinned-kernel version/exit sequence have passed. Prefix and full image readback and
comparison, sustained exchanges, physical speed, filters and programming
completion still require qualification for the independent AutoCal backend.
No independent RAM readback or interrupted-flash recovery has been established.
An ordinary PcmHammer factory/CLI integration must also explicitly own and
close the native device: the current Vehicle disposal path alone does not
unconditionally dispose its Device. Cancellation must cover initialization as
well as the later vehicle operation.

An AutoCal backend does not establish the AL5 erase/program/verification or
interrupted-write recovery path. AL5 `live_write_enabled` and `ready_to_flash`
remain false.

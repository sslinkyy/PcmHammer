# AutoCal V2 transport reconstruction, 2026-10-30

PcmHammer now contains a file-only decoder for complete AutoCal host envelopes.
A separate, isolated developer probe also completed an independent USB model
query with EFILive closed. PcmHammer does not yet contain an AutoCal device
backend. The existing OBDX adapter,
AL5 direct reader, adapter selection and AL5 write gates are unchanged.

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
implementation. No AutoCal device backend or live send path was added.

The actual PcmLibrary build passed with the same three pre-existing CS1998
warnings. The setup-response harness passed 144 boundary assertions and all
17 saved setup replies, for 284 assertions in the saved-corpus run. All 89
focused Python tests passed; 28 current source/helper digests matched the
reports. Its corpus
chooses command context explicitly for field testing; it does not infer a
transaction match. Source digests and validation are recorded in the
[offline test receipt](AUTOCAL_SETUP_SPEED_TEST_20261030.json).

```powershell
dotnet run --project Tools/AL5/AutoCalSetupResponseTest.csproj --verbosity quiet
python -B -m unittest discover -s Tools/AL5 -p test_autocal_speed_trace.py
python -B -m unittest discover -s Tools/AL5 -p test_autocal_speed_vm.py
```

## Remaining integration work

USB packetization and independent adapter discovery are corroborated for the
documented sessions. The bounded local model query also passed after a
user-reported USB power cycle. Raw VPW transport requires additional evidence.
Bus initialization, filters, 1x/4x transitions, request completion, error
handling and authorization behavior remain unresolved for an independent
PcmHammer backend. No generic command replay or live writer is implemented.

An AutoCal backend would also not prove the AL5 erase/program/verification or
recovery path. `live_write_enabled` and `ready_to_flash` remain false.

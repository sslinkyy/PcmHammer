# AutoCal model test using PcmLibrary

`Tools/AL5/AutoCalModelProbe` is a standalone Windows x64 developer test. Its
project references the existing `Apps/PcmLibrary/PcmLibrary.csproj`, so the
reply is decoded by the built `PcmLibrary.dll`. It is not registered in
PcmHammer's adapter selector and implements no vehicle transport.

The isolated hardware test on 2026-10-30 passed: one 14-byte request produced
the same 20-byte `ACV2` reply as the earlier Python tests. PcmLibrary verified
the outer CRC, both queue checks were empty, and the device handle, library
and file pin were released successfully. The process exited with code zero.
The separate [C# result](AUTOCAL_CSHARP_MODEL_20261030.json) pins the saved
receipt, journal, preflight, sources and assemblies.

The build completed with no warnings or errors; the offline harness passed
92 assertions, including partial/error replies, cancellation, delayed calls,
failed cleanup, telemetry failures, exclusive evidence files, and valid-CRC
replies with the wrong route or model. These simulated failures do not prove
native-driver failure behavior on hardware.

The only application request is the 14-byte model query already established
by [static analysis](AUTOCAL_IDENTITY_STATIC.json), the independent
[USB-corroborated trial](AUTOCAL_DIRECT_MODEL_20261030.json), and the
[reported power-cycle repeat](AUTOCAL_COLD_MODEL_20261030.json).

## Scope and identity

The test is deliberately restricted to the reviewed AutoCal serial
`AC3NCHH5`, VID/PID `0403:E4A3`, and the installed x64 D2XX library with SHA256
`91185415e0a1cd8ad09a5b644130554867ee4c4975c7aa71ee6da15d2645d9a2`.
The primary ABI header is also hash-checked. Another device or driver requires
separate review; there is no command-line override for the serial, DLL or
request bytes.

The eight D2XX bindings are enumeration, exact-serial open, fixed timeouts,
queue status, write, read and owned-handle close. The application contains no
reset, purge, EEPROM, bus configuration or arbitrary-send operation. Driver
implementation side effects are separate from this application allowlist.

The state machine requires an empty receive queue before one complete write.
It never retries a partial write. Up to eight bounded reads collect exactly
20 reply bytes. The shared decoder validates the complete frame and outer
CRC; the test additionally requires route `01 82` and payload `ACV2\0`.
Metadata and the trailing byte remain uninterpreted. Extra queued data fails
the test rather than being discarded.

## Offline checks

From the checkout root:

```powershell
dotnet build Tools/AL5/AutoCalModelProbe/AutoCalModelProbe.csproj --verbosity quiet
dotnet LocalOnly/AutoCalModelProbe/bin/AutoCalModelProbe.dll --self-test
dotnet LocalOnly/AutoCalModelProbe/bin/AutoCalModelProbe.dll --plan
```

No arguments also selects the file-only plan. The self-tests use a fake
device boundary and the real PcmLibrary decoder; they do not load D2XX.
The plan reads source, assembly, DLL and header identities without opening an
adapter. Build output remains in ignored `LocalOnly/AutoCalModelProbe`.

## Isolated model query

Keep the AutoCal OBD plug physically disconnected and EFILive closed. The
explicit `--obd-disconnected` argument records the operator's physical setup
assertion; software cannot verify the disconnected cable.

```powershell
dotnet LocalOnly/AutoCalModelProbe/bin/AutoCalModelProbe.dll --query-model --obd-disconnected --receipt LocalOnly/AutoCalModelProbe/csharp_model_01.json
```

The receipt must be a new direct child of `LocalOnly/AutoCalModelProbe`.
Both receipt and journal are exclusively created before loading D2XX. Existing
files are never overwritten. Use a new filename for a separately justified
test, rather than automatically retrying a failed session.

The DLL is held against write/delete sharing while loaded, and its dependencies
are resolved from System32. The exact serial is re-enumerated on each run;
an old USBPcap address is never used to select the device.

## Cleanup and limitations

A shared monotonic budget blocks new device operations after 20 seconds.
Ctrl+C requests cancellation and cleanup. A native call already in progress
may outlive that deadline; the test cannot claim that such a call completed.
The owning process remains responsible for the handle.

If close or library cleanup fails, the process retains the corresponding
handle, DLL and file pin and waits for explicit `retry-close` input. End of
input does not authorize termination or repeated queries. Logging failures
cannot skip the owned cleanup path.

Successful model identification proves only this bounded adapter-local
exchange. It does not qualify raw VPW initialization, request/reply handling,
1x/4x transitions, controller programming or recovery. Live AL5 writes remain
disabled.

No additional USBPcap recording or power cycle was performed between the
earlier Python power-cycle check and this C# test. The OBD-disconnected state
remained the user's physical setup assertion. The saved Windows preflight
confirmed the exact healthy PnP identity and no EFILive/HAPI process before
execution. No controller operation ran.

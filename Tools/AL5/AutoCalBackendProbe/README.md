# Experimental AutoCal backend probe

This developer executable uses the production `AutoCalDevice` and `AutoCalChannel`
with a pinned Windows D2XX transport. It is separate from normal adapter selection.
Neither this probe nor the ordinary PcmHammer factory enables AutoCal flashing.

Build and inspect the plan without loading a driver or opening USB:

```powershell
dotnet build Tools/AL5/AutoCalBackendProbe/AutoCalBackendProbe.csproj --verbosity quiet
dotnet run --project Tools/AL5/AutoCalBackendProbe/AutoCalBackendProbe.csproj --no-build -- --plan
dotnet run --project Tools/AL5/AutoCalBackendProbe/AutoCalBackendProbe.csproj --no-build -- --plan-e54-osid-read
dotnet run --project Tools/AL5/AutoCalBackendProbe/AutoCalBackendProbe.csproj --no-build -- --plan-e54-ram-copy
```

The USB-only profile requires the OBD cable physically disconnected and EFILive,
its Control Panel, and other adapter owners closed. Its exact eight commands
query the model, perform the reconstructed setup, and perform recorded cleanup.
The first real run accepted all eight exchanges and closed the native owner;
see [the setup receipt](../../../Docs/AL5/AUTOCAL_BACKEND_USB_SETUP_20261030.json).
These responses establish host protocol acceptance, not physical bus behavior.

The separate E54 identity profile passed one ordinary query on the isolated
spare E54/LB7 bench. Confirm its current physical connection and power state
before invoking it again. It uses the observed ordinary identification setup, submits exactly one
`6C 10 F0 3C 0A` request, then only receives for a bounded interval. It accepts a
matching OS-ID reply for the saved bench baseline `15189044`, preserving the
observed nine- or eleven-byte response. The two extra bytes in the latter are
opaque; neither reply proves which firmware execution state produced it.

The first real identity run submitted one `6C 10 F0 3C 0A` and received
`6C F0 10 7C 0A 00 E7 C4 34 44 4E`, matching OS `15189044`. Across the complete
setup/query/cleanup session, all eight TX and eight RX envelopes passed outer
CRC checks. The journal has no short transfers or replays; final receive queues
were empty, native disposal completed and no native owner remained retained.
See the [identity receipt](../../../Docs/AL5/AUTOCAL_E54_IDENTITY_20261030.json)
for exact source/build hashes, command order and limitations. This is D2XX
journal evidence, without an independent electrical speed measurement.

Live invocation forms (not automatic test steps):

```text
--usb-setup --obd-disconnected --serial SERIAL --receipt NEW_ABSOLUTE_PATH.json
--e54-osid-read --isolated-e54-bench --serial SERIAL --receipt NEW_ABSOLUTE_PATH.json
--e54-ram-copy --isolated-e54-bench --serial SERIAL --receipt NEW_ABSOLUTE_PATH.json
```

Each receipt must be a new direct child of `LocalOnly/AutoCalBackendProbe`.
Both profiles journal raw TX/RX and source, assembly, and native-library hashes.
The exact request guard rejects any unlisted command, different payload,
reordered request, replay, or incorrect continuation after a partial write.
There are no arbitrary payload, file, address, retry, security algorithm,
speed-change, kernel-selection, erase, or flash-programming options.

The RAM-copy profile is a separate bounded experiment. It verifies the fixed
OS-ID, suppresses normal chatter, uses PcmHammer's existing E54 seed/key and RAM
upload-permission methods, and sends only the pinned kernel's final 267 bytes
to `FF97E0..FF98EA`. A matching six-byte `76 00` response is retained with its
last byte opaque. Observing it does **not** establish that the bytes were written
correctly. The experiment stops without executing code, querying a kernel, or
sending controller/adapter protocol cleanup. A bench power cycle is required
before a future attempt. Native USB resources are still closed explicitly.

The full RAM-kernel coordinator is tested offline, including exact kernel
version, exit and post-exit identity. Its live `--e54-kernel-info` invocation is
blocked before loading a native driver; `--plan-e54-kernel-info` remains available
for inspection. Existing traces contain no stock RAM-copy acknowledgement,
so live execution must not proceed just because a simulated copy succeeds.
See [the evidence gap](../../../Docs/AL5/AUTOCAL_STOCK_RAM_COPY_ACK_GAP_20261030.json).

After failure the tool sends no additional protocol cleanup and closes only
owned host resources. A native operation still running at its deadline remains
owned until completion; a close failure retains ownership for explicit retry.
The successful recorded cleanup sequence is not proof that the physical bus is
OFF or at 1x. The probe reports physical speed and bus transmission counts as
unmeasured. `vpw_payload_commands_started/completed` refer to host command
submission, not an electrical measurement.

Offline tests:

```powershell
dotnet run --project Tools/AL5/AutoCalChannelTest.csproj --verbosity quiet
dotnet run --project Tools/AL5/AutoCalDeviceTest.csproj --verbosity quiet
dotnet run --project Tools/AL5/AutoCalProbeProfileTest.csproj --verbosity quiet
dotnet run --project Tools/AL5/AutoCalKernelProbePolicyTest.csproj --verbosity quiet
dotnet run --project Tools/AL5/AutoCalKernelProbeSessionTest.csproj --verbosity quiet
```

The backend's 4x transition and physical programming remain unqualified. The
existing AL5 direct reader and write gates are unchanged. The successful
identity test establishes one matching exchange only; it does not qualify
kernel transfer, full readback, programming acknowledgements, verification or
interrupted-write recovery. AutoCal remains absent from normal adapter selection.

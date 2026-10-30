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
dotnet run --project Tools/AL5/AutoCalBackendProbe/AutoCalBackendProbe.csproj --no-build -- --plan-e54-kernel-info
dotnet run --project Tools/AL5/AutoCalBackendProbe/AutoCalBackendProbe.csproj --no-build -- --plan-e54-read-baseline
dotnet run --project Tools/AL5/AutoCalBackendProbe/AutoCalBackendProbe.csproj --no-build -- --plan-e54-read-prefix
```

The USB-only profile requires the OBD cable physically disconnected and EFILive,
its Control Panel, and other adapter owners closed. Its exact eight commands
query the model, perform the reconstructed setup, and perform recorded cleanup.
The first real run accepted all eight exchanges and closed the native owner;
see [the setup receipt](../../../Docs/AL5/AUTOCAL_BACKEND_USB_SETUP_20261030.json).
These responses establish host protocol acceptance, not physical bus behavior.

The separate E54 identity profile passed one ordinary query on the isolated
spare E54/LB7 bench. Confirm its current physical connection and power state
before invoking it again. It uses the observed ordinary identification setup,
submits exactly one `6C 10 F0 3C 0A` request, then only receives for a bounded
interval. It accepts a
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
--e54-kernel-info --isolated-e54-bench --serial SERIAL --receipt NEW_ABSOLUTE_PATH.json
--e54-read-baseline --isolated-e54-bench --serial SERIAL --receipt NEW_ABSOLUTE_PATH.json
--e54-read-prefix --isolated-e54-bench --serial SERIAL --receipt NEW_ABSOLUTE_PATH.json
```

Each receipt must be a new direct child of `LocalOnly/AutoCalBackendProbe`.
All profiles journal raw TX/RX and source, assembly, and native-library hashes.
The prefix-read profile reserves a private `.readback.bin` sibling and reads
only 64 bytes at address zero, after the same kernel and flash-ID checks.
It requires the pinned prefix SHA-256
`5b20a24c0d5c5618de617dd929c4baffe7ba4cf151648398f68f0105bd43a5d9`
before exit and the final OS-ID. It sends no CRC queries, cannot retry the
read, and cannot qualify a full image. Its limits are 44 VPW payload commands,
51 host commands and 180 seconds. This diagnostic changes only the requested
read extent; adapter setup, kernel and speed remain as in the full-read attempt.
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

The first real COPY-only run submitted the exact 267-byte tail and received
`6C F0 10 76 00 78`. It recorded eight VPW requests and six VPW replies, with no
`36 80` execute, flash operation, DTC clear, controller exit or speed change.
All twelve application TX and ten RX envelopes passed their outer CRCs; the
copy packet also passed its block checksum and matched the pinned source tail.
The native owner closed with zero retained owners. See the
[COPY-only receipt](../../../Docs/AL5/AUTOCAL_E54_RAM_COPY_20261030.json).

This establishes the reply shape, not the copied RAM bytes. The final `78`
remains opaque. The tool stopped without further protocol traffic and required
a bench power cycle; that session contains no subsequent cold-reset identity
check. It did not execute uploaded code or query a kernel version.

After the owner reported power-cycling the bench and AutoCal, a separate
ordinary identity run again returned OS `15189044`. Its eight TX/eight RX
host envelopes passed all outer CRCs; recorded cleanup succeeded, both receive
queues were empty and the native owner closed. See the
[post-copy reset receipt](../../../Docs/AL5/AUTOCAL_E54_POST_COPY_RESET_20261030.json).
The physical reset and 13.8 V supply were user-attested. This confirms ordinary
communication after that reported reset; it does not validate the earlier RAM
contents, full kernel execution or interrupted-flash recovery.

The RAM-kernel coordinator passes its offline checks, including exact kernel
version, exit and post-exit identity. After the separate Copy-reply and cold-reset
identity observations, `--e54-kernel-info` enables only the fixed isolated-bench
experiment. It sends the two pinned RAM fragments once, requires the observed
Copy reply before Execute, and requires the exact Execute reply before the known
kernel-version query. Only a matching version permits exit; the exact exit ACK
and one ordinary OS-ID check after a 10-second settling margin must also pass.
Failures stop without another upload or controller cleanup. Flash erase/program,
arbitrary kernels and speed transitions remain absent. Full image reads are
confined to the separate baseline-read mode described below.
The first actual kernel-info session completed successfully. Its COPY and
EXECUTE packets exactly matched the pinned 2,027-byte asset. The replies were
`6C F0 10 76 00 78` and `6C F0 10 76 80 78`, followed by exact known version
`6C F0 10 7D 00 6A B1 78 EC 36`. Exit returned `6C F0 10 60`; an ordinary OS-ID
request 10,018 ms later returned `15189044`. Recorded adapter cleanup and native
closure succeeded. See the
[kernel execution receipt](../../../Docs/AL5/AUTOCAL_E54_KERNEL_EXECUTION_20261030.json).

The journal contains twelve VPW requests and ten VPW replies within nineteen
TX/seventeen RX host envelopes, all with valid outer CRCs. Fourteen zero-byte
native reads occurred while waiting for the two upload replies; no upload was
replayed. The known version establishes execution of the relevant pinned kernel
path, without independently verifying every RAM byte. No flash read, CRC,
erase/program, DTC-clear or speed-change operation ran.

The earlier
[evidence-gap inventory](../../../Docs/AL5/AUTOCAL_STOCK_RAM_COPY_ACK_GAP_20261030.json)
remains unchanged and covers its original saved traces. COPY-only, post-reset
identity and kernel execution are separate observations. None qualifies flash
programming or interrupted-flash recovery.

The separate `--e54-read-baseline` profile reuses the production
`CKernelReader.ReadRunningKernelContents` after the same pinned kernel-version
check. Its policy admits only flash ID `00894471`, 128 sequential 4,096-byte
reads covering `000000..07FFFF`, and seven controller CRC ranges. Every data
reply must have the exact route, mode, address, length and block checksum.
The assembled image must match the saved GT baseline SHA-256
`a3b010af7e04df03be699198920aac26ba0645c2ad608e72eacf0bc3970beb58`.
All seven CRCs must also match before exit and the ordinary OS-ID check.

Data reads cannot replay. Only the current CRC query may repeat, up to six
submissions per range, as required by the existing verifier's polling loop.
The command budget is 392 VPW payloads and 399 host commands, with a 900-second
overall deadline. A new `.readback.bin` sibling is reserved before opening USB;
an image is usable only when its receipt reports verified completion. Failure
stops protocol traffic and closes owned host resources; it does not reset or
re-upload automatically. Flash programming and speed changes remain blocked.

The first physical baseline-read attempt **failed at its first data request**;
see the [failed-read audit](../../../Docs/AL5/AUTOCAL_E54_FULL_READ_BLOCKED_20261030.json).
Setup, initial OS identity, pinned kernel version and flash ID `00894471` passed.
The single `6D 10 F0 35 01 10 00 00 00 00` request was submitted at 3,130 ms.
No bytes were returned by subsequent D2XX reads over five logical 10-second
receive windows. The generic reader's attempted resend was blocked before
native submission. Zero data blocks and CRC ranges completed; the reserved
readback file is empty. No exit/reset or adapter protocol cleanup followed, and
the native owner closed with zero retained owners. A bench power cycle was
required at the stopped session's boundary.

The journal contains eighteen TX and thirteen RX host envelopes, all 31 outer
CRCs valid, including fourteen VPW requests and nine replies before the data
wait. It has 475 zero-byte native reads after the data request; this is separate
from the five logical timeouts. These host observations do not identify whether
the kernel or adapter caused the missing data. The full-read path remains
unqualified, and the previous successful kernel-info result does not change
that conclusion.

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

The pinned RAM-kernel version/exit/ordinary-identity sequence has passed on the
isolated E54 bench. Full flash readback, the backend's 4x transition, programming
and interrupted-write recovery remain unqualified. The existing AL5 direct
reader and write gates are unchanged. AutoCal remains absent from normal
adapter selection.

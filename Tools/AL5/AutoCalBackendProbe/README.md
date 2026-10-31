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
dotnet run --project Tools/AL5/AutoCalBackendProbe/AutoCalBackendProbe.csproj --no-build -- --plan-e54-read-prefix-recorded-setup
dotnet run --project Tools/AL5/AutoCalBackendProbe/AutoCalBackendProbe.csproj --no-build -- --plan-e54-read-prefix-submode-zero
dotnet run --project Tools/AL5/AutoCalBackendProbe/AutoCalBackendProbe.csproj --no-build -- --plan-e54-read-prefix-acknowledged
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
--e54-read-prefix-recorded-setup --isolated-e54-bench --serial SERIAL --receipt NEW_ABSOLUTE_PATH.json
--e54-read-prefix-submode-zero --isolated-e54-bench --serial SERIAL --receipt NEW_ABSOLUTE_PATH.json
--e54-read-prefix-acknowledged --isolated-e54-bench --serial SERIAL --receipt NEW_ABSOLUTE_PATH.json
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
The separate recorded-setup experiment keeps that prefix request and kernel
unchanged. After ordinary identity it sends `8603{0100F401}` then
`8604{010010000000}`; after verified kernel execution it sends
`8604{000000000000}` before flash identification and the prefix read. These
three fixed adapter commands follow the configuration lifecycle in saved
EFILive reads. Their firmware meaning and effect on reception remain unknown.
Both the device and native request guard reject replay, changed commands and
incorrect phase ordering. The limit becomes 54 host commands; the 44 VPW
payload and 180-second limits remain unchanged. Its separately recorded bench
experiment accepted all three configuration exchanges but still delivered no
data through AutoCal; the paired result is described below.
The exact request guard rejects any unlisted command, different payload,
reordered request, replay, or incorrect continuation after a partial write.
There are no arbitrary payload, file, address, retry, security algorithm,
speed-change, arbitrary kernel-selection, erase, or flash-programming options.

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

The separate `--e54-read-prefix` profile requests exactly 64 bytes at address
zero after the same kernel-version and flash-ID checks. Its baseline match is
explicitly scoped to `baseline-prefix`; it permits no CRC query or data replay,
and does not establish full-image verification. A matching checksum and pinned
prefix hash are required before exit and the ordinary OS-ID check.

Its [first physical attempt also failed](../../../Docs/AL5/AUTOCAL_E54_PREFIX_READ_BLOCKED_20261030.json),
from source `d138947`. The single request `6D 10 F0 35 01 00 40 00 00 00` was
submitted at 3,150 ms. No bytes reached D2XX afterward: 285 native reads returned
empty through 33,193 ms, about 30 seconds after the request. Two ordinary empty
receive windows completed; a still-pending native read hit the third window's
deadline and faulted the channel. That late transfer completed empty with no
error, and disposal finished with zero retained owners. This differs from the
full-read run's five empty windows followed by a blocked resend. Neither stop
reason explains the missing memory reply.

The prefix run again passed setup, initial identity, exact kernel version and
flash ID. It recorded eighteen TX and thirteen RX host envelopes, all outer
CRCs valid, containing fourteen VPW requests and nine replies. No data, prefix
comparison, CRC, exit/reset or protocol cleanup followed; its reserved readback
file is empty. Both prefix and full-image reads remain unqualified.

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
python -m unittest discover -s Tools/AL5 -p test_derive_autocal_ack_kernel.py
```

The [paired GT observation](../../../Docs/AL5/AUTOCAL_E54_GT_PREFIX_20261030.json)
captures the missing prefix reply independently. With checked 1x/source-`10`
LISTEN ONLY settings, the GT received a 77-byte physical frame whose VPW CRC,
block checksum and 64-byte baseline digest all match. Nine earlier ECM replies
match AutoCal's journal in order. AutoCal delivered zero bytes in 477 subsequent
native reads over 50.053 seconds. The GT returned OFF and restored its saved
settings; AutoCal closed without a channel fault or retained owner. This
establishes that the prefix response appeared on VPW but was not delivered by
AutoCal under the tested configuration. It does not identify the firmware cause,
qualify arbitrary reception or establish complete/lossless monitoring.

The [paired recorded-setup experiment](../../../Docs/AL5/AUTOCAL_E54_GT_PREFIX_RECORDED_SETUP_20261030.json)
produced the same delivery gap. All three added configuration exchanges were
accepted at their required phases. The GT again received the correct prefix
reply, with valid VPW CRC, block checksum and baseline digest, after nine shared
reply anchors. AutoCal returned zero bytes in 379 subsequent native reads over
40.052 seconds. A pending read reached its deadline, then completed empty;
owned resources closed with zero retained owners. No exit/reset was sent, so
the next experiment requires a bench power cycle. Acceptance of these setup
commands does not establish their internal firmware effect.

The separate `--e54-read-prefix-submode-zero` experiment changes exactly one
data byte in an owned memory copy of the pinned 2,027-byte RAM kernel: file
offset `0x7AE`, RAM address `0xFF98AE`, changes `01` to `00` in the Mode35 reply
template. The original source file must first match its existing SHA-256 and
is never modified. The derived image must match
`17a351715bbdd366cf77e33ad5d0b801fa0747f2d31c57478ad3bb409ee58fe3`.
Instruction bytes, version, read request, length, address and baseline data
remain unchanged. The RAM upload checksum is recalculated by the production
packet builder. The kernel already includes the template byte in its running
reply checksum; the host validates that checksum on the original raw reply.

This tests the observed difference between PcmHammer's `36 01` data reply and
saved EFILive `36 00` replies. The original configuration is retained; combining
it with the recorded-setup experiment is rejected. It adds no Mode75
acknowledgement, leaving that other observed EFILive difference unresolved.
Only the fixed 64-byte prefix can be read, with the existing 44 VPW / 51 host
command and 180-second bounds. Success still requires exact prefix validation,
kernel exit and ordinary OS identity. The ordinary three-argument payload
parser still requires submode `01`; only this explicit experiment selects `00`.
The [paired zero-submode test](../../../Docs/AL5/AUTOCAL_E54_GT_PREFIX_SUBMODE_ZERO_20261030.json)
confirmed that the changed `36 00` reply appeared on VPW with the correct
64-byte baseline and checksums, but AutoCal still delivered no data. The two
submitted RAM fragments reconstruct the pinned derived image exactly; changing
the submode alone did not resolve reception. AutoCal completed 478 subsequent
native reads with zero bytes over 50.036 seconds, exhausted five receive
windows, and closed without a channel fault or retained owner. The GT completed
capture, verified OFF and restored its saved settings. No prefix was received
through AutoCal, so no exit/reset or ordinary post-exit identity followed.
Another bench power cycle is required before a subsequent live experiment.

The separate `--e54-read-prefix-acknowledged` experiment keeps the zero-submode
control and adds a fixed `6D F0 10 75 01 54` response before its data reply.
The [offline derivation audit](../../../Docs/AL5/AUTOCAL_E54_ACK_KERNEL_DERIVATION_20261030.json)
records the exact three checked patch regions and their source evidence.
The Mode35 dispatch branches through a stub within the existing 22-byte
metadata region at file `0x794`; the stub calls the unchanged short-frame
sender, then branches to the original Mode35 handler before address and length
extraction. The image stays 2,027 bytes and MessageBuffer stays at `0xFF98EB`.
The original source file is unchanged. Attribution from the repurposed metadata
is preserved here and in the plan/audit: `(c)2026 pcmhacking.net`, an Antus /
Gampy collaboration, GPL-3.0-only.

The exact ACK-plus-zero image SHA-256 is
`eca54a2661baa317c02f96cd19a4e4bdac5a79a4c264f5154662e12e1c519664`.
Twenty-five bytes differ from the original asset, or twenty-four from the
zero-submode control. No receive-buffer relocation or additional RAM extent is
used. The short sender returns before the original handler reconstructs its
address/length registers. Its physical completion and back-to-back frame timing
remain unqualified.

The stub emits `54` before the original parser and relies on the host's exact
64-byte, address-zero request guard. It does not reproduce EFILive's general
length/address validation or negative `51`/`52`/`53` responses.

The host requires exactly one matching Mode75 acknowledgement before the
checksum-valid submode-zero prefix. Missing, changed, repeated or out-of-phase
acknowledgements stop the session. Already queued receive bytes after a valid
prefix also prevent exit in this profile; that check does not establish future
bus silence. Adapter configuration, request extent and command budgets remain
the same as the zero-submode control. The first
[physical acknowledged-prefix test](../../../Docs/AL5/AUTOCAL_E54_ACK_PREFIX_SUCCESS_20261030.json)
passed: exact ACK, valid 64-byte baseline prefix, kernel exit and ordinary
OS 15189044. All 13 received VPW replies also match the GT capture in order.
The GT returned OFF and restored settings; AutoCal closed with zero retained
owners. This qualifies only the fixed prefix experiment. Full-image reads,
4x operation, flashing and recovery remain unqualified. No flash operation is enabled.

The pinned RAM-kernel version/exit/ordinary-identity sequence has passed on the
isolated E54 bench. Full flash readback, the backend's 4x transition, programming
and interrupted-write recovery remain unqualified. The existing AL5 direct
reader and write gates are unchanged. AutoCal remains absent from normal
adapter selection.

The separate `--plan-e54-read-baseline-acknowledged` previews the full-image
ACK-plus-zero profile without opening USB. Its live form is
`--e54-read-baseline-acknowledged --isolated-e54-bench --serial SERIAL --receipt NEW_ABSOLUTE_PATH.json`.
It uses the same exact RAM asset as the successful prefix test, but requests
128 sequential 4096-byte blocks and seven CRC ranges. Every block requires
its own ACK. The original full-read and prefix profiles remain separate.
The first full-image transfer matched the baseline, but controller-CRC delivery failed; flashing remains unavailable.

## Full acknowledged transfer: CRC delivery gap (2026-10-30)

The isolated E54 test at 1x delivered all 128 acknowledgements and all 128
4,096-byte data blocks through AutoCal. Offline journal reconstruction validates
every block checksum and the full 512 KiB baseline SHA-256. The independent
GT capture replays completely and contains all 265 AutoCal VPW replies in order.

Verification then failed: the GT captured two checksum-valid replies for the
first CRC range (address 0x60000, length 0x20000, CRC D6703728), but neither
appears in AutoCal receive data. Zero of seven CRC ranges were accepted.
The receive deadline faulted the channel; that describes the stop, not the
cause of missing delivery. The session correctly failed without kernel exit
or post-exit identity, and the reserved readback file stayed empty. Native
ownership closed with zero retained owners; adapter protocol cleanup did not
complete. The GT restored settings and returned its network OFF. A bench power
cycle is required before another test.

Evidence: `AUTOCAL_E54_ACK_FULL_CRC_GAP_20261030.json` under Docs/AL5; reproduce
offline with `audit_ack_prefix_success.inspect(full=True)` using the pinned
local artifacts. This establishes complete data delivery for one fixed 1x
experiment, not a verified successful read, 4x capability, flashing or recovery.
No flash operation ran and live writes remain disabled.

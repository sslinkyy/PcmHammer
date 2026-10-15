# OBDLink SX adapter-local inspection

Physical inspection on 2026-10-14 (2026-10-15 04:34 UTC) confirmed:

- Port: COM8, FTDI VID 0403 / PID 6015.
- Hardware: OBDLink SX r4.2 (STDI).
- Firmware: STN1130 v4.0.1, dated 2014.05.02 (STI/STIX).
- Bootloader: 2.16 (STDIX).
- Selected protocol: SAE J1850 VPW, ELM protocol 2 (ATDP/ATDPN).
- Reported protocol baud: 10417 (STPBRR). This is a local setting readback,
  not an observed vehicle signal or a 4X transition test.
- Reported supply voltage: 0.0 V (ATRV). This does not independently verify
  physical wiring or vehicle network state.

All eleven explicit queries returned prompts at 115200 UART baud. No reset,
firmware change, protocol selection/open, monitoring, OBD request or vehicle
payload was sent. The port was closed after inspection. Existing adapter
settings were queried without changing them; Windows UART configuration was
set to 115200 8N1 with DTR/RTS and flow control disabled.

Private raw TX/RX evidence, including device serial and runtime counters:
`Tools/AL5/LocalOnly/OBDLinkSX_20261014/inspection-01.json` (ignored by Git).

## Repeating an adapter-local inspection

Run from `Tools/AL5` with the currently verified SX port and a new output path:

```powershell
python inspect_obdlink.py --port COM8 --output LocalOnly/OBDLinkSX_20261014/inspection-02.json
python -m unittest test_obdlink_inspect -v
```

The script permits only exact local query strings. It rejects bare CR,
arbitrary commands, resets and protocol operations. It stops on pending input,
unexpected identity, missing prompt, oversized response or trailing data;
there is no baud search, reset, command retry or repeat-last-command fallback.
Errors preserve partial responses in the output report. It does not implement
capture or flashing and cannot verify the vehicle network is OFF.

## Capture decision remains open

This establishes adapter identity and working host communication. It does not
establish passive reception, packet completeness, sustained capture throughput
or 4X VPW support. PcmHammer's existing ScanToolDeviceImplementation explicitly
sets Supports4X and SupportsStreamLogging to false. These software flags are
limitations of the existing integration, not independent hardware tests.

The [OBDLink reference manual, revision F](https://www.scantool.net/scantool/downloads/682/obdlink_frpm_f.pdf)
documents the local ST identity queries and STPBRR. It states STPBR baud changes
are not supported for J1850 (section 8.6). A modern manual is command-reference
evidence, not proof that this older firmware can capture a complete AL5 flash.
Do not use STPBR to attempt a 4X VPW transition.

A splitter purchase alone would not resolve these missing capture capabilities.
Live monitoring and vehicle transmissions remain outside this inspection.

## USB-only monitor probe, 2026-10-14

The user explicitly confirmed that the SX was powered by USB only, with its
OBD plug physically unplugged. A separate `probe_obdlink_monitor.py` tool was
then used. The original identity-only tool still rejects monitoring commands.

Observed on the same COM8 / STN1130 v4.0.1 / SX r4.2:

1. Confirmed identity, already selected VPW protocol 2, and 0.0 V readback.
2. Sent `STMA` followed by CR. The adapter echoed the command and remained
   active for the one-second observation interval, without a prompt or error.
3. Sent a single `x` byte, without CR. The adapter returned exactly CR + `>`.
   It did **not** print `STOPPED` on this empty, disconnected bus.
4. A following `STI` query returned the expected firmware identity.

The first probe required `STOPPED` and therefore stopped without a subsequent
query, preserving the prompt-only response. A second probe specifically checked
the older firmware's prompt-only exit and confirmed the subsequent local query.
Both raw reports are retained under the ignored evidence directory as
`usb-monitor-01.json` and `usb-monitor-02.json`.

No protocol-open command, vehicle payload, reset, firmware update or settings
setter was used. The adapter was closed after each probe. The probe requires
explicit physical-disconnection confirmation and does not implement vehicle
capture. Voltage alone is not a disconnection interlock.

This confirms command acceptance and entry/exit behavior on an empty bus. No
VPW frames were supplied, so reception and electrical silence remain unproven.
The absence of SX UART output while waiting is not evidence of electrical
silence at the OBD pins.

### Source checks and remaining uncertainty

The [official 4.0.1 archive](https://www.scantool.net/scantool/downloads/213/obdlink_sx-4.0.1.zip)
contains the dated SX changelog. Its 3.3.0 entries describe improvements to UART
cancellation and monitoring protocol detection/saving; the 4.0.1 entry describes
a CAN flow-control fix. This corroborates historical monitoring support but
does not establish silent VPW operation. Archive SHA-256:
`343a1fab1ab457d093fa6b4167805abfa347ce843ffe71dc3dd4aa7db937575f`.
Only the changelog was extracted; no updater, library or firmware was executed.
Member hashes and names are retained in `firmware-changelog-source.json`.

The old-looking `stn1100-frpm-preliminary.pdf` download URL currently served
the modern 78-page OBDLink FRPM F. It must not be cited as a contemporary manual
for 4.0.1. The observed prompt-only exit differs from that manual's documented
`STOPPED` sequence.

The [ELM327 datasheet](https://elmelectronics.com/wp-content/uploads/2020/05/ELM327DSL.pdf)
describes original ELM327 monitoring as suppressing J1850 in-frame responses.
This is compatibility evidence, not a measurement or a firmware-level proof for
STN1130. The OBDLink manual separately documents `ATIFR0` as disabling IFR
transmission; no IFR setting was changed in these probes. CAN silent-monitoring
settings such as `STCMM` do not establish VPW silence.

Qualification still requires an isolated powered VPW source and an independent
means to attribute electrical activity to the SX. Check connection, monitor
entry, sustained reception, monitor exit and USB disconnect/reconnect, including
messages that request an IFR. A second decoded packet log alone cannot rule out
malformed pulses, contention or loading; electrical measurement is needed for
that claim. Frame completeness and 4X reception are separate checks. Do not use
an AL5 programming session as the first qualification test.

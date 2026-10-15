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

# PcmHammer writer USB comparison

The GT can act as PcmHammer's E54 writer while USBPcap records its USB traffic.
This is a different experiment from using the GT as a passive listener beside
AutoCal. USBPcap observes bytes delivered over USB; it cannot recover a VPW
message the GT never forwards or independently establish what was on the wire.

`Tools/AL5/pcmhammer_usb_capture.py` compares a saved PcmHammer debug log with
selected GT bulk-IN completions. It performs no hardware access. Supply the
recorded USB bus, device address and IN endpoint, and explicitly inspected DVI
byte windows after any adapter bootstrap text. Separate CLI opens can introduce
additional bootstrap spans. Every excluded span remains in the report with its
length and hash; the parser never resynchronizes silently.

The comparison preserves message order, duplicates, malformed bytes, short
acknowledgements and PCAP offsets. It distinguishes logged Mode 36 test transfers
(`44`), ordinary copies (`00`), execute transfers (`80`), and Mode 3D/05 erase
requests. These TX classifications describe the debug log, not independently
verified USB OUT delivery. A copy can target RAM or flash. Neither a request nor
a matching RX stream alone proves successful flash programming.

Run the tool with `--help` for its required file and selection arguments. Output
creation is exclusive. For focused offline validation, from `Tools/AL5` run:

```powershell
python -B -m unittest test_pcmhammer_usb_capture test_usb_serial_capture -q
```

The 27 tests passed on October 30, 2026. They cover stream fragmentation,
duplicate and reordered replies, explicit excluded spans, timestamp changes,
malformed messages, USB completion errors, resource limits and exclusive output.
They do not qualify hardware behavior.

For a bench experiment, identify the exact controller and adapter, retain a fresh
full backup and pin the writer/kernel inputs before programming. Keep one owner
of the GT serial port: the passive `obdx_capture.py` process must not run beside
PcmHammer using that same GT. Capture setup must complete before PcmHammer opens
the port. Preserve capture cleanup failures alongside any useful captured bytes.

PcmHammer's `--test-write` transfers packets without erasing/programming flash.
The current AL5 checkout's ordinary `--write` selects the full-image operation
and skips matching sectors; writing an unchanged backup is not proof of actual
programming. This comparison tool does not add a force option or change any
writer. Live AL5 writes remain disabled.

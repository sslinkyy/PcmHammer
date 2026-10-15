# Allison LCT playback and diagnostic DLL inspection

Offline inspection, 2026-10-15. No adapter, controller, Allison DOC process or
target DLL was executed. The working Mode 0x23 reader and live-write gates are
unchanged. This is diagnostic/playback evidence, not a qualified flash exchange.

## Playback source and complete framing

User input: `C:\Users\ty_ma\AppData\Local\Temp\1k2k Demo.log`, 1,455,294 bytes.
SHA-256: `89dca2f2ee9f230f04fec2a5ec7aa960e0bbd87954365029e3610195980625a7`.
An identical private copy is retained under
`Tools/AL5/LocalOnly/AllisonPlayback_20261015/`.

The ASCII header declares Allison Playback File, J1939, LCT and version 2.0.
Observed layout, decoded without scanning ahead or skipping malformed records:

- Header through `[Static]`: bytes 0..73.
- 277 static records: bytes 74..8383.
- Separator `CR LF [Data] CR LF`: bytes 8384..8393.
- 48,230 data records: bytes 8394..1455293.
- All 48,507 records are exactly 30 bytes. Zero bytes remain unexplained by
  framing; this does not establish complete capture of any original session.

Each record contains a four-byte prefix, an 18-byte message slot and an opaque
eight-byte trailing region. The low little-endian prefix word consistently
specifies 11..18 valid message bytes in this file. The high word is zero except
for five data records with value 0x0100; its semantics remain unknown.

Valid message bytes begin with a four-byte big-endian timestamp followed by an
RP1210-style header and payload. Timestamp units are unverified. Static values
span 1193..11262; data values span 11274..712103, without backwards movement.
Every stored message has raw PGN bytes `00 EF 00` and subsequent bytes `06 03 F9`.
Priority 6, source 0x03 and destination 0xF9 are header interpretations, not proof
of a complete bidirectional wire trace. No separate outbound-record direction
has been established.

## Stale bytes must not become programming evidence

For all 19,331 shortened data messages, unused message-slot bytes exactly match
the same positions in the previous record. They are not part of the current
message. Static unused/trailing regions also contain request-looking remnants;
their meaning and ownership are unverified. Initial whole-file byte searches
therefore overstate the amount of apparent request traffic.

The two data messages beginning 0x44 are each exactly one payload byte long.
Any bytes after that byte are outside their declared message length. The two
static messages beginning 0x7F contain `7F 2A 14 FE FD FC FB 23` and
`7F 2A 24 FA F9 F8 F7 23`; their presence does not establish flash failure.

Actual payload leading bytes are limited to 0x44, 0x52, 0x59, 0x60, 0x62,
0x6A, 0x6C, 0x7C and 0x7F across both sections. Request-looking 0x12/0x20/0x2C
occurrences in unused/trailing bytes must not be treated as captured requests.
The native PCCS erase helper's internal status or buffer meanings cannot be
assigned to unrelated DOC payloads merely because a byte value is equal.

Static payload `62 1A 40 55 32 41` contains U2A. This is an identification
candidate consistent with the existing U2A comparison image; it does not qualify
that image for the user's AL5 operating software or establish a programming path.

## Supplied diagnostic DLLs

`Gen3Tcm.dll` is managed x86 CIL, assembly 21.5.0.0 targeting .NET Framework
4.7.2, MVID `56881137-7005-4703-843d-023dcc02981b`.
SHA-256: `1acc57865921028e7a5d40835bc107a7a3fe2bed5c28694f289950729ebcadee`.
REA metadata Evidence:
`ev_bed5a236bec7f224d3956cf9550b8f3b425f17c55336d1337851cbb6779911c0`.
Resources include `AllisonDOC.Gen3.LCT3.LCTPossibleDataItems.xml.enc`; resource
names alone do not disclose the data or encryption scheme.

REA's complete managed-member operation returned unavailable coverage because
its representation exceeded the 64-MiB budget. This was not retried unchanged.
A focused execution-free fallback using private dnfile 0.17.0 and dncil 1.0.2
inspected ConnectionLCT3 and the LCT COM interface. Method token 0x06000156
(`ConnectionLCT3.Playback`) contains calls to LCT `StartPlayback`, playback
`GetHeaderTag` and `RetreiveStaticData`. These are static call sites, not observed
execution or a reconstructed complete call path. Obfuscated string operands were
not treated as decoded source literals. The selected LCT interface declares
diagnostic/data-map, device-control and playback operations; similarly named
reprogramming methods on WTEC/CEC classes must not be attributed to LCT.

`LctTransBusRules.dll` is a native x86 PE with no CLI metadata.
SHA-256: `023185650cddbd015a16eef4a8d58b2d6e173519ff07dc6434cb1552a55389c8`.
REA/Ghidra observed these paths without executing the DLL:

- Function 0x100072F7 selects J1939 versus J1850, constructs LCT/version-2.0
  playback headers and sets up read/request engines. Evidence:
  `ev_98251b7ebdc60c465bd5f9cd6bbb53b092fd537952dd8f0148c551d7fa4f800d`.
- Function 0x1001029E handles playback, validates header-derived settings and
  distinguishes J1939/J1850. Decompiled string/type artifacts remain unreliable.
  Evidence: `ev_9b3557a3b6d01a9af3fbb818f02260eb9dbe3d6a03be33ec2bce3c6c831fcddb`.
- A reference to `ProcessRead1850DataDPIDSetupResponse` was found at 0x1000C428,
  but Ghidra did not define a containing function. That handler was not claimed
  as reconstructed. Windows P0 analysis-database mutation was not used.

The native REA session was closed with a reusable snapshot. Exact CIL fallback
results, source identities, raw log and full decoded record report are retained
in the private directory above. The source DLLs were not modified.

## Offline tool and remaining questions

From `Tools/AL5`:

```powershell
python inspect_allison_playback.py 'PATH\1k2k Demo.log' --output 'PATH\new-report.json' --include-records
python -m unittest test_allison_playback test_offline test_authorization
```

The standard-library-only decoder supports the observed J1939/LCT/version-2.0
header and fixed-slot layout. It preserves partial results on invalid lengths
or truncation, never resynchronizes, and refuses output overwrite. Raw messages,
unused slot bytes, trailing bytes and opaque flags remain separate. All transport,
programming, recovery and flash-readiness gates remain false.

Follow-up [LCT handler tracing](LCT_HANDLER_TRACING.md) binds the managed LCT
interface to native handlers and reconstructs selected command tables offline.

Next: inspect the playback-manager producer/reader to establish prefix flags and
timestamp units, then trace the native LCT diagnostic dispatcher to assign
evidenced service meanings. A complete programming, verification and recovery
exchange remains missing. This file does not validate SX passive reception,
noninterference or 4X capture.

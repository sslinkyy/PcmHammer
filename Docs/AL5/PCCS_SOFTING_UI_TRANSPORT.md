# PCCS Softing UI selection and outgoing transport

Follow-up: [genuine J1850 programming route](PCCS_J1850_PROGRAMMING_ROUTE.md)
finds the separate TJ1850 class and inherited programming entry points.
The SPX driver implementation and complete AL5 VPW sequence remain unavailable.

2026-10-15, continuation of `PCCS_BUNDLED_DRIVER_FILTER_BEHAVIOR.md`.
PCCS's Softing CANusb UI branch normalizes the protocol to CAN unless IESCAN
is selected. The outgoing SoftUSB wrapper then constructs standard/extended
CAN calls. This explains why a J1850 menu choice need not become a J1850
connection. No application settings or hardware state were changed.

## UI normalization resolves the literal-name uncertainty

The owner reported former Softing CANcard/250 kbit CAN and current Softing
CANusb/J1850 selections. Those labels identify the intended family; a
runtime-loaded file path/digest remains unobserved.

The protocol combo's index-3 branch assigns literal J1850 at `0x5E820A`.
Later in the same configuration handler, the Softing CANusb control at object
+`0x3A0` is tested at `0x5E88C0`. If selected, `0x5E88D5` assigns SOFTUSB.DLL
to library global `0x828FDC`. The following `0x5E88E4..0x5E8904` comparison
retains IESCAN, but otherwise assigns CAN to protocol global `0x828FE4`.
The library-prefix selection path at `0x5E76CC..0x5E76FA` binds SOFTUSB to
the same control. These source bindings distinguish the adapter branch from
an unrelated protocol selector.

The previous native SoftUSB name checks supplied literal J1850 directly to
the DLL selector. They remain valid tests of that selector but do not model
this UI rewrite. The UI path provides a concrete earlier transformation:
applying Softing CANusb with J1850 selected reaches a SOFTUSB.DLL/CAN state
at this boundary. Actual saved settings, full configuration application,
connection and bus behavior are separate from the modeled slice.

New `emulate_pccs_softusb_ui.py` executes that native adapter-check branch
with guarded synthetic control getter and Delphi string operations. Five
contexts cover checked J1850/CAN/IESCAN/CAN:Baud=500 and unchecked J1850.
The checked branch also sets device word `0x828FEC` and timing global
`0x81D1D0` to 1; the unchecked case stops before the next adapter branch.
The actual UI, string runtime and full configuration handler do not run.

A separate command-line J1850 path at `0x7D4244..0x7D4286` selects
SPX1850.DLL through the alternate-library setting. That is not evidence that
SoftUSB implements VPW. It must not be silently composed with the Softing
CANusb UI path or treated as a verified programming route.
Pointer `0x81F194` resolves to the same library storage `0x828FDC`; the
command-line and UI rules are different writers of that setting, not proof
that both libraries are active together.

## Actual outgoing wrapper constructs CAN arguments

New `emulate_pccs_softusb_send.py` runs native SoftUSB export
`_RP1210_SendMessage@20`, `0x4021B8..0x40223E`, stopping before either lower
`CANPC_send_data` call. It supplies a synthetic queue-level result and
replaces one strictly guarded ID copy. The native byte-order helper runs.
No DLL/import/API/device call occurs.

The initial byte selects the conversion: zero means two-byte BE ID,
standard selector 0, payload offset 3 and length `message_length - 3`;
every nonzero value means four-byte BE ID, extended selector 1, payload
offset 5 and length `message_length - 5`. There is no distinct VPW sender
in this exported wrapper. Nonzero format bytes 2 and 6C are deliberately
included in tests to show the absence of a format-equals-1 check; this is
not validation of arbitrary input as a CAN or VPW frame.

Synthetic initial buffer `00 07 E2 01 A2 AA AA AA AA AA AA` reaches the
lower-call boundary with CAN ID 7E2, standard selector and eight payload
bytes. Ordinary buffer `01 18 EF 03 F9 35` reaches it with ID 18EF03F9,
extended selector and payload 35. These are constructed call arguments,
not transmitted packets or a complete session replay.

The wrapper's signed queue-level comparison permits values below 70 and
returns low-word error 89 otherwise. A negative synthetic queue result also
takes the conversion path; this observation does not qualify real error
handling. Eight contexts cover both formats, nonzero format bytes, queue
69/70/-1 and a zero-payload header. This bounded model requires complete
headers and at most eight payload bytes; malformed/truncated message
handling by the real wrapper is not fully modeled.

## Evidence and remaining gates

SoftUSB source SHA-256:
`ad0e619e90e35e84b468ddcd5cfd9c0e3c1b3b7eaa674776c91cb03bd6c9236d`.
Winrw32 source SHA-256:
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.

REA Evidence
`ev_29cbc3882c2688e15ec00d900f501a680358ef3169399871479891bd8e432d6b`
resolves the complete 135-byte SendMessage body. The read-only session was
closed and saved as `pccs-softusb-outgoing-20261015.snapshot.json`, with four
records. Anchored source and native observations are privately retained as
`softusb-outgoing-source.json` and `native-softusb-outgoing.json` under
`Tools/AL5/LocalOnly/PCCS_20261015/QuickWriteTrace/`.
The UI/selection observations are retained in
`pccs-j1850-softusb-ui-source.json`, `pccs-softusb-label-source.json`,
`pccs-softusb-ui-native.json` and `PCCS_J1850_SOFTUSB_UI_FINDINGS.md`.

Validation: **197 tests passed, no skips**, including ten new test methods,
with pinned PCCS/DOC/SoftUSB/Vector inputs and both S2 images present. Focused
command from `Tools/AL5`, with optional Unicorn, `AL5_PCCS_EXE` and
`AL5_SOFTUSB_DLL` pointing to the existing pinned inputs:

```powershell
python -m unittest test_pccs_softusb_ui test_pccs_softusb_send -q
```

The earlier SoftUSB receive model already converts both corresponding receive
layouts. The UI rewrite and sender now support a coherent host-side CAN
interpretation. They do not prove driver/hardware acceptance, AL5 response
production, successful programming or interrupted-flash recovery. No actual
VPW support is inferred from the J1850 label. The working Mode `$23` reader
is unchanged; live-write gates remain closed and all reports keep
`ready_to_flash=false`, `live_write_enabled=false` and `would_send=[]`.

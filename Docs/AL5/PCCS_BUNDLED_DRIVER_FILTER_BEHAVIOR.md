# Bundled PCCS drivers: filter commands and receive behavior

2026-10-15, continuation of `PCCS_DRIVER_FILTERS_BUS.md`.
Two bundled RP1210 wrappers, SoftUSB and Vector, have unconditional return-zero
SendCommand exports. Commands 3/17/5 do not install or combine filters in those
exports. SoftUSB's native receive converter can produce both of the host
layouts required by the examined initial E2 and ordinary identification paths.
Actual hardware event delivery, selected driver and AL5 compatibility remain
unproven. Live writes remain disabled.

## Driver identity matters

The available files do not establish which DLL a running PCCS session selects.
This pass inspects the bundled implementations, not an observed loaded module.
Their preferred image addresses are source anchors rather than runtime load
addresses. They must not substitute for an unexamined DPA/NEXIQ/Noregon driver.

The prior PCCS command-17/5 emitters have driver-name guards involving
DR1210/DG/NXULNK/NULN2R32 and DLAWIR/NORWIR/V3PUWA. The bundled SoftUSB and
Vectcdxl32 names are not those guarded names. Their no-op handlers therefore
do not establish the behavior of the drivers eligible for those filter blocks.
The owner's follow-up below narrows the selected family; the runtime-loaded
file path and digest remain unverified.

### Owner-reported Softing selection and protocol mismatch

Follow-up: [UI normalization and outgoing transport](PCCS_SOFTING_UI_TRANSPORT.md)
finds that the Softing CANusb UI branch rewrites J1850 to CAN before connection.
The literal-name selector checks below do not include that earlier rewrite.

The owner subsequently reported the previous selection as Softing CANcard with
250 kbit CAN, and the current selection as Softing CANusb with J1850. This
narrows the driver family; it does not verify the runtime-loaded file path or
digest. The bundled SoftUSB implementation remains the pinned analysis target.

The new native protocol-selector checks execute `0x402151..0x40219F`, after
successful reset is assumed and before chip initialization. This wrapper reads
only the protocol name's first byte. Initial letters I/X/Y select flag pairs
1/0, 0/1 and 1/1 respectively. Other names, including CAN and J1850, select
0/0 and then reach the same CAN-chip initialization helper. Six contexts cover
CAN, J1850, IESCAN, XCAN, YCAN and 1MEGCAN. This also shows why a menu label or
a successful connect return cannot independently establish protocol support.

There is no distinct J1850/VPW branch in this selector. The current J1850 menu
selection therefore must not be used as evidence that this SoftUSB wrapper
operates a VPW network. The earlier CAN selection is consistent with the
CAN-related PCCS path under investigation, but actual bus behavior remains
unverified. No application setting was changed.

Static comparison of bundled SoftCD32.dll
(`f0ae6fca492996da23e8facdc73100172d205b7d1e5b41fbfc6b1a7ee52639e9`)
also shows CAN-chip initialization and first-character protocol selection;
it additionally has a leading-1 branch absent from this SoftUSB selector.
This is a bounded comparison, not qualification of the former CANcard setup.
Private `softing-protocol-selector-source.json` preserves both anchored windows;
`native-softusb-protocol-selection.json` records the updated native audit.

## SoftUSB command handling and initial acceptance

SoftUSB.dll SHA-256:
`ad0e619e90e35e84b468ddcd5cfd9c0e3c1b3b7eaa674776c91cb03bd6c9236d`.
The `_RP1210_SendCommand@16` export is the nine-byte function
`0x402528..0x402530`: establish a stack frame, zero EAX, restore the frame,
return while popping 16 argument bytes. It reads no arguments and writes no
filter state. The exported handler cannot implement a mask list, additive
filtering or discard-all state. A zero return here is not installation proof.

ClientConnect invokes initialization helper `0x402084`. That helper requests
`CANPC_set_acceptance` through an import thunk at `0x4020C7`, passing four
zero arguments. It tests the return before proceeding to mode/FIFO/chip-start
setup. This is a static initialization request, not verified hardware state.
The lower bundled CanUSB.dll, SHA-256
`55da089670719b6f6713e5427f96806c6a1d4a720744e91a5006610f4d787b10`,
complements the second and fourth arguments while constructing its device
command at `0x10002F40`. Zero inputs therefore become all-one mask fields in
that constructed command. Actual device interpretation and installation are
outside this pass; this does not assert a physical pass-all configuration.

## SoftUSB can convert both receive forms

`emulate_pccs_softusb_receive.py` runs the actual exported ReadMessage entry,
its byte-index/jump tables, selected standard/extended branch, byte-order
helper and return. CANPC_read_ac is a guarded replacement supplying an event;
three buffer-copy calls are also guarded replacements. No import is invoked.

The actual dispatch tables select event 1 to `0x4022A7` and event 9 to
`0x40230E`. Event 1 produces four BE timestamp bytes, format 0, two BE ID
bytes, then payload; its reported length is payload length plus 7. Event 9
produces timestamp, format 1, four BE ID bytes, then payload; its reported
length is payload length plus 9. These exactly account for the previously
traced PCCS receive-buffer offsets and length adjustments.

Six synthetic contexts cover initial ID 7EA, ordinary ID 18EFF903, identifier
boundaries, an empty payload and ordinary payload `35 00`. Both relevant IDs
reach conversion without a mask comparison in their executed wrapper branches.
This is host conversion of supplied CANPC events, not proof those events can
arrive from the hardware or that AL5 answers both requests.

The native converter copies eight payload bytes even for a shorter reported
length; the tool supplies an eight-byte synthetic backing buffer and exposes
only the reported output length. It does not infer validity of bytes beyond
that reported length or treat an empty packet as a valid AL5 reply.

## Vector command handling and acceptance-reset requests

Vectcdxl32.dll SHA-256:
`9068a4cadf75fd663f6c1f66d07938ebef153492c53fc9e46eb49d00571893f5`.
Its `_RP1210_SendCommand@16` export at `0x44D5FC..0x44D604` has the same
return-zero behavior. `emulate_vectcdxl_filter_entry.py` executes that native
stub with argument/state reads forbidden. Commands 3, 17, 5 and invalid values
all return zero, including cases with invalid, unread command-buffer pointers.

A separate bounded ClientConnect slice `0x44D056..0x44D089` calls
`xlCanResetAcceptance` with numeric selectors 1 and 2, checking the low word
of each result. A first failure skips the second call. The tool substitutes
both calls and preserves the selectors numerically; it does not claim their
API/device semantics or actual acceptance state. Nine contexts cover the
command stub and reset success/failures, including a high-word-only result.

## Evidence, limitations and next trace

SoftUSB REA Evidence `ev_79b5b39df0f5e5dfccca58f3d81e77e723b6578394e38834a70649f65ef1c998`
resolves the nine-byte command body. Initialization Evidence
`ev_10a4ff37c90c6e45008518b174dd105b1168d20a18fc35169e675d17a58d1632`
resolves helper `0x402084` and its import calls.

ReadMessage Evidence
`ev_55ab7116ab7e5f2a4715597bc0b81579ed59dde04771f48cc38ae8f3c4611e80`
has an unresolved computed dispatch and only 55 provider-defined body bytes.
The native model supplements it with anchored original dispatch-table and
branch bytes. No function body was expanded or created; no provider
completeness claim follows from that model. The read-only session was closed
and saved as `pccs-softusb-filter-20261015.snapshot.json` with three records.

Private evidence is under `Tools/AL5/LocalOnly/PCCS_20261015/QuickWriteTrace/`:
`softusb-filter-receive-source.json`, `native-softusb-receive-reviewed.json`,
`vectcdxl-filter-source.json`, `vectcdxl-filter-native.json`,
`VECTCDXL_FILTER_FINDINGS.md` and the saved snapshot. Reports pin source
digests, execution boundaries, synthetic callbacks and qualification limits.

Validation: **187 tests passed, no skips**, including ten new test methods,
with pinned PCCS/DOC/SoftUSB/Vector inputs and both S2 images present. Focused
command from `Tools/AL5`, with optional Unicorn and `AL5_SOFTUSB_DLL` /
`AL5_VECTCDXL_DLL` pointing to the pinned existing files:

```powershell
python -m unittest test_pccs_softusb_receive test_vectcdxl_filter_entry -q
```

The host-side layouts can coexist in SoftUSB's converter. The masks inferred
from PCCS buffers cannot establish a loaded driver's filter behavior: these
two wrappers do not interpret those commands at all. Resolve the selected DLL
before attributing behavior to the user's setup, then trace its initialization
and hardware-facing receive path. AL5 replies, programming and interrupted-flash
recovery remain unproven. No driver DLL, Windows API, COM, adapter or controller
was executed. The Mode `$23` reader and live-write gates are unchanged.

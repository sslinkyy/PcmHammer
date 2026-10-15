# LCT native COM gaps — offline, 2026-10-15

The four unnamed managed COM slots are now identified from the installed
DLL's embedded type library. Their native bodies do not establish a direct
activation of group 2 (`10 10`) or a flash-transfer entry point.

## Source and method ownership

Source: installed `LctTransBusRules.dll`, SHA-256
`023185650cddbd015a16eef4a8d58b2d6e173519ff07dc6434cb1552a55389c8`.
The embedded MSFT TYPELIB resource is 7,716 bytes, SHA-256
`58bce0ba1e2025500f39b43d525db25a54d573619f903b6d553668cb8af677db`,
starting at DLL file offset 484,680. Resource identity is TYPELIB / 1 / 1033.
Its method records, name table and vtable byte offsets resolve the missing
slots in the interface-order binding at native vtable `0x1005E99C`.

- Slot 10, `LCT`, property getter, native `0x100121A6`: queries a stored
  object's interface using IID `00020400-0000-0000-C000-000000000046`
  (`IDispatch`) and the caller's output pointer. The stored object is read
  from COM-this + `0xA0`. No request-selector activation appears in this path.
  Returning an object does not establish all behavior reachable through it.
- Slot 11, `ReturnToNormalMode`, native `0x1000F6BB`: invokes group 3 (`20`),
  checks host status, and conditionally invokes group 5
  (`2A 14 FE FD FC FB` / `2A 24 FA F9 F8 F7`). Its final output copies the
  host result. The type-library name does not establish controller-mode
  transitions or interrupted-flash recovery.
- Slot 20, `CancelSnapshot`, native `0x10007046`: writes DWORD 1 to the
  caller's output and returns zero. Its 18-byte native body contains no call.
  No actual cancellation operation appears in this implementation.
- Slot 26, `SmartDetect`, native `0x1000FF6E`: temporarily changes the
  group-3 timeout field at `0x1007298C` to 250, invokes group 3, restores the
  previous field and copies host status to the caller. It does not select 2.

All four declarations return HRESULT. The output parameters are marked
out/retval (flags `0xA`): the getter uses a pointer type descriptor targeting
IDispatch; ReturnToNormalMode and SmartDetect target SHORT; CancelSnapshot
targets LONG. Raw descriptors and record offsets are retained rather than
inferring an ABI solely from a display signature.

## Evidence and limits

The static type-library declarations independently corroborate native behavior;
they do not prove controller responses. No DLL loading, COM registration or
activation, transport, adapter or vehicle interaction was performed. No native
function body was modified or promoted from undefined code.

The Ghidra body for slot 10 ends at `0x100121FF` and follows an epilogue helper
at `0x10012241`; it is not treated as a standalone emulated complete routine.
Slot 11 contains compiler stack/exception artifacts in its decompilation.
Native object dispatch, reflection and external modules remain open boundaries.
The earlier managed audit's four unknown slots are now named; its bounded
negative search is still not a whole-application dead-code proof.

Private records are retained under
`Tools/AL5/LocalOnly/AllisonPlayback_20261015/GapTrace/`, including the extracted
type library, source-bound parser reports and
`lct-com-gap-trace-20261015.snapshot.json` (74 Evidence records, 30 primitive
bindings). Earlier private interface-order reports preserve the original
managed `_VtblGap` labels as source evidence; this report supplies their names.

REA Evidence:

- Resource: `ev_8ab078df4638c03cc63c8db51f160d8be0567f39038b5289a5294dbdac46855d`.
- LCT getter: `ev_4ce828332c65effd8b2d82a6943aece8e82d2fbd40fc7890af248fc305dbf028`.
- ReturnToNormalMode: `ev_3a11b7c841525bd9815e573de09429fbb272137734f62a9f753498d235fee7d1`.
- CancelSnapshot: `ev_29c062e9c173862af253a4b148ae4a7f5859fd4797b65559961f7869aeb058ad`.
- SmartDetect: `ev_65855c6ae52b6527308f81ff97ee514c321117827b4cc16dc131bc3f3bc60b46`.

This closes the unnamed native-slot lead. Further DOC investigation must follow
the returned object or computed/external activation; the known slots provide
no new programming chain. The separate PCCS loader/transfer path remains a
more direct programming lead. Erase, transfer, final verification and recovery
remain unproven. Live AL5 writing remains disabled.

## Reproduce offline

`audit_lct_typelib.py` uses only the Python standard library. It discovers the
PE resource, inventories seven type declarations, decodes all 28 IEcuInterface
method records and verifies the four native vtable entries against the pinned
DLL. Original bytes, file offsets, type descriptors, parameter flags and
unknown interpretations are retained. It refuses changed source hashes and
existing output files. Resource references and pointer chains are bounded by
their source spans; cyclic metadata is rejected.

From `Tools/AL5`:

```powershell
$env:AL5_LCT_DLL = 'PATH\LctTransBusRules.dll'
python audit_lct_typelib.py $env:AL5_LCT_DLL --output 'PATH\new-typelib-audit.json'
python -m unittest test_lct_typelib test_lct_event_setup test_lct_command_tables test_lct_session_callbacks test_allison_playback test_offline test_authorization test_pccs_methods -q
```

Validation: 62 tests passed, including nine type-library tests with the actual
pinned DLL. Malformed bounds/records, resource and descriptor cycles, a long
pointer chain and output preservation are checked. Real-input coverage skips
explicitly when the corresponding local DLL or emulator dependency is absent.
The working Mode `$23` reader and all live-write gates are unchanged.

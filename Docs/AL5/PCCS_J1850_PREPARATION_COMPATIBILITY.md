# PCCS J1850 preparation and programming compatibility

The examined PCCS initialization explicitly disables programming, erase and
recovery controls when selecting TJ1850. Inherited programming methods are
therefore insufficient evidence of a supported AL5 VPW programming path.
This refines the earlier [class-route findings](PCCS_J1850_PROGRAMMING_ROUTE.md).
No hardware communication or live writing was enabled.

## Observed initialization restriction

Pinned Winrw32.exe SHA-256:
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.

At `0x7D4CA9..0x7D4D16`, effective protocol `J1850` or command-line `/J1850`
selects TJ1850. The following `0x7D4D16..0x7D4E46` instructions disable named
controls. Preserved form metadata binds these fields to `Write1`, `Write3`,
`Erase1`, `WriteProgramButton`, `WriteCalButton`, `ProgramandCalButton`,
`RecoverTCM1` and additional programming controls. Menu setter `0x521DD8`
stores false and selects flags `3` for the imported `EnableMenuItem` thunk;
button calls pass false to virtual slot `+0x74`. These are static observations;
no Windows API or UI setter ran.

This establishes an initialization restriction. Later re-enablement and
programmatic bypass have not been exhaustively traced.

## Unresolved inherited-writer compatibility

The ordinary WriteCal caller at `0x7C625F` passes the selected controller
index. Inherited WriteData at `0x5B4C90..0x5B4CA8` forwards its byte unchanged
to virtual `+0x00`; TJ1850 places that supplied byte directly in its host
envelope. With synthetic selected controller `3`, this chain would address
`03`, whereas the overridden read/security methods construct target `18`.
There is no translation within the examined forwarding instructions.

The constructor loads separate `[Controllers]` and `[J1850]` maps into
`+0x68C04` and `+0x68C0C`. Installed configuration maps Transmission to `3`
and `$18`, respectively. Common selection reads the former. Direct accesses
to the latter in the bounded TJ1850 scan occur in the `0x726070` parameter/
DPID loop and produce a local address; they do not establish a remap of the
common selected-controller global. Aliases and computed writes remain a limit.

QuickWrite has another compatibility gap: inherited code at `0x5B4FF5`
calls base CAN-envelope helper `0x5A8C58` directly. Inheriting virtual `+0x18`
does not prove that QuickWrite uses TJ1850's overridden dispatcher. Actual
reachability and successful programming remain unproven.

## Offline preparation gate

`Tools/AL5/emulate_pccs_j1850_prepare_gate.py` executes original instructions
in the inherited EnterWrite interior gate, beginning at `0x5B8C1D`. It assumes
preceding security prerequisites and stops before any preparation method:

- Nonzero global `0x81D144` with zero `0x81D158` reaches virtual `+0x60`,
  independently of the alternate-route byte. TJ1850 binds this slot to
  `0x7251B8`, with DL=1, ECX=0 and pending stack argument 1.
- Otherwise, alternate byte zero reaches ordinary builder `0x5B8ED6`.
- Otherwise, it reaches alternate preparation `0x5B8CAA`.

The model checks 24 contexts, substitutes a state-preserving `+0x44` callback
and suppresses the 50-unit delay. It does not establish real `+0x44` effects,
execute startup, or join these stages into a complete authorized session.
Source pin, TJ1850 bindings, PC coverage, instruction budget, stack balance
and bounded writes are enforced.

Separately inspected original startup bytes `0x7251B8..0x7252B6` construct
host buffer `01 8C 18 F1 10 10`. The waiting branch accepts reply lengths
8..127 with header bytes `8C F1`, then service `50` sets status zero and
`7F` sets status two. These checks do not establish an AL5 programming
authorization handshake. The gate makes clear that `10 10` is conditional,
not the universal inherited preparation request.

## Verification and remaining work

Validation: 219 tests passed with no skips, including five preparation-gate
tests and the existing pinned native/offline suite. Focused command from
`Tools/AL5`, with Unicorn 2.1.4 and `AL5_PCCS_EXE` configured:

```powershell
python -m unittest test_pccs_j1850_prepare_gate -q
```

Private evidence under `Tools/AL5/LocalOnly/PCCS_20261015/QuickWriteTrace/`:
`native-j1850-prepare-gate.json`, `pccs-j1850-prepare-source.json`,
`pccs-j1850-programming-exclusion-source.json` and
`PCCS_J1850_PROGRAMMING_EXCLUSION_FINDINGS.md`.

These findings narrow PCCS's usefulness as a VPW programming reference; they
do not rule out another tool's AL5 programming protocol. The missing
SPX1850 driver, controller-side programming and interrupted-erase recovery
remain unresolved. Mode `$23` reading is unchanged. Reports retain
`transport_used=false`, `live_write_enabled=false`, `ready_to_flash=false`
and `would_send=[]`.

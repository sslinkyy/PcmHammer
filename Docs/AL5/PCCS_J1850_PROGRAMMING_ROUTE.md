# PCCS J1850 programming route and missing SPX driver

2026-10-15, continuation of `PCCS_SOFTING_UI_TRANSPORT.md`.
PCCS contains a genuine TJ1850 class with inherited programming entry points
and its own dispatcher, security, reads and reset. This is stronger evidence
than a protocol label. It does not yet establish working AL5 programming over
VPW: SPX1850.DLL was not found in the checked locations or selected older
installer, and its physical translation remains unavailable. Live writes stay
disabled.

## A different communication class is selected

At `0x7EB15B..0x7EB198`, effective protocol J1850 selects descriptor
`0x723B48`, whose self pointer is VMT `0x723BA0`, rather than base descriptor
`0x5A4004` / VMT `0x5A405C`. Both use constructor `0x5E440C`. A separate
initialization branch `0x7D4CA9..0x7D4D16` also admits the /J1850 first-argument
condition. The RTTI name is TJ1850 and its parent descriptor is `0x5A4004`.
These are source selection/binding observations, not runtime class captures.

Selected VMT bindings are now read directly by the offline tool:

- WriteData +10=`0x5B487C`, QuickWriteData +18=`0x5B4F80`, EnterWrite
  +3C=`0x5B87AC` and EndWrite +40=`0x5B93E4` are inherited.
- Dispatch +00=`0x724668`, ReadData +2C=`0x7259F8`, RequestSeed
  +34=`0x725D68`, SendKey +38=`0x725EB4`, slot +54=`0x725350` and reset/identify
  +70=`0x726734` replace their base-class targets.

The inherited programming bodies make a host programming route plausible.
They still perform virtual calls, so the earlier base-CAN dispatcher, read,
security and reset models cannot establish this class's complete behavior.
In particular, the earlier QuickWrite clear/requalification results describe
the base reset at `0x5DCB40`, not the TJ1850 reset at `0x726734`.

## Different envelope and startup/security helpers

New `emulate_pccs_j1850_envelope.py` executes native
`0x72468B..0x7246F6`, stopping before SendMessage callback +8 at `0x7246F7`.
The actual instructions construct host buffer:

```text
01 8C <target> F1 <payload>
```

The callback's pending arguments are connection word +2C, buffer +528B0,
payload length plus four, zero and zero. Only the Delphi payload-copy helper
is replaced. The leading 01 is source data in this envelope; it must not be
interpreted using the SoftUSB CAN format-byte model. No SPX driver call,
physical VPW encoding or checksum generation executes.

Four synthetic contexts cover supplied target 18/session payload 10 10,
other target/payload values and the model's declared 128-byte resource bound.
That bound is not a discovered protocol maximum. The report also audits twelve
selected VMT slots and their source offsets/digests, preserving the distinction
between inherited and overridden targets.

Static helper observations provide further protocol leads: startup helper
`0x7251B8` constructs `01 8C 18 F1 10 10`; the security overrides construct
service 27/01 and 27/02 with a big-endian key word from object +29E. Slot +54
constructs service 3C before virtual dispatch. These are constructed host
requests, not a qualified AL5 session or successful security exchange.

The TJ1850 reset clears +72D90, iterates 256 indexed flags and calls
`0x726514` before further family/status gates. Its complete identification,
QuickWrite selection and failure/recovery behavior remain tracing targets.
Inherited entry-point names alone do not prove those prerequisites pass for
the user's AL5.

## SPX driver search and what it establishes

The checked installed Allison tree, retained Car Tuning trees and broader
Program Files (x86) filename search did not supply SPX1850.DLL. Exact checks
of Windows, System32 and SysWOW64 also found no such file. The broader search
reported access denied for an unrelated HP log directory; other unexamined
archives and paths remain outside this absence claim.

The supplied calibration bundle contains `trffullinstall38.exe`. It was read
as an archive, not executed. Its InstallTCMReflash.msi compound file contains
an embedded cabinet with 137 file records; none is SPX1850.DLL. Source chain:

- Installer SHA-256:
  `6cef0fb610b73c20e4e6b7c332cbf45ba2f6bfc78d0bf893a57907ef42b88e25`.
- MSI SHA-256:
  `73a14d74f37a64c25885cc0e95c8357cf89a8c0cb49bb06bd0d7c5688e3ce09f`.
- Embedded cabinet SHA-256:
  `d772da98cfd30a9e493586dd0a09d7559d0628215f8ed9116edd6497ca789b40`.

Installed Allison DOC documentation labels the J 44652-A connection diagram
J1850-VPW. That supports the adapter/protocol association; a diagnostic
connection diagram does not prove PCCS's programming sequence or recovery.
No instructions in that document were carried out.

The missing DLL or its driver installer is needed to examine the actual
transport implementation. It may interpret, translate or augment the host
envelope; that behavior cannot be filled in from the SoftUSB driver or names.

## Evidence and offline boundary

All new PCCS bindings pin Winrw32.exe SHA-256
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.
New observations use anchored original bytes, Delphi metadata and bounded
Unicorn 2.1.4 emulation, with no provider metadata mutation. Existing REA
evidence is retained; no new provider completeness claim is made.

Validation: **203 tests passed, no skips**, including six new test methods,
with pinned PCCS/DOC/SoftUSB/Vector inputs and both S2 images present. Focused
command from `Tools/AL5`, with optional Unicorn and `AL5_PCCS_EXE` configured:

```powershell
python -m unittest test_pccs_j1850_envelope -q
```

Private evidence under `Tools/AL5/LocalOnly/PCCS_20261015/QuickWriteTrace/`:
`pccs-j1850-class-route-source.json`, `PCCS_J1850_CLASS_FINDINGS.md`,
`pccs-j1850-envelope-bindings.json` and
`spx1850-bounded-artifact-search.json`. Installer/MSI/cabinet bytes remain
private. No installer, PCCS entry point, DLL, Windows transport API, COM,
adapter or controller was executed. Mode `$23` reading remains unchanged;
all reports keep `live_write_enabled=false`, `ready_to_flash=false` and
`would_send=[]`.

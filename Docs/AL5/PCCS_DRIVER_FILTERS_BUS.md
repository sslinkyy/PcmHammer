# PCCS driver filters and bus configuration

Follow-up: [bundled driver behavior](PCCS_BUNDLED_DRIVER_FILTER_BEHAVIOR.md)
finds no-op SendCommand handlers in bundled SoftUSB/Vector wrappers and
models both SoftUSB receive formats. Runtime driver selection remains unknown.

2026-10-15, continuation of `PCCS_FALLBACK_TRANSPORT_TRANSITION.md`.
PCCS uses RP1210 callbacks and requests pass-all filtering after connection.
The ordinary target-3 identification branch skips a later target-F3 filter
replacement. This supports host-side coexistence of the initial and ordinary
envelopes, conditional on driver configuration and successful commands. It
does not establish actual AL5 replies, bus wiring or a working flash session.

## Driver identity and connection

The loader in `0x5D37A0` resolves UTF-16 export-name strings and stores the
resulting addresses in the communication object. The source binds object +4
to `RP1210_ClientConnect`, +8 to `RP1210_SendMessage`, +`0x0C` to
`RP1210_ReadMessage`, and +`0x10` to `RP1210_SendCommand`. Both decorated and
undecorated names are tried. Thus the previously traced shared callback slots
have concrete API identities, rather than being inferred from their arguments.
No DLL is loaded by the offline analysis.

On the general connection branch at `0x5D4AB7..0x5D4ADF`, ClientConnect receives
window 0, selected device, protocol-string pointer, transmit/receive sizes
`0x8000`, and final parameter 0. Its returned AX becomes connection word +`0x2C`.
The common success check at `0x5D4C59` accepts signed values 0 through 127.
It sets host status zero and connected byte +`0x2E` to 1, then requests
SendCommand 3 with length zero at `0x5D4C97`.

`emulate_pccs_driver_connect.py` runs the native general connect-call phase
and common success phase with an explicit handoff. String conversion,
ClientConnect and SendCommand are guarded synthetic callbacks. Eight contexts
cover client IDs 0/1/127, rejected results 128/-1, a filter-command error and
supplied protocol strings CAN, CAN:Baud=250 and IESCAN. Protocol selection,
loader behavior, retries and full initialization are excluded.

The modeled filter command returning error 9 still leaves host status zero
and connected byte 1 at the immediate return boundary `0x5D4C9A`. Those
fields were set before the command. They cannot alone establish that a driver
accepted the requested filters. The callback itself could have additional
effects that this synthetic return does not reproduce.

## Bus settings and limits

Installed `Devices.xml` contains 15 exact `TCM_1K2K3rd` connection records;
all request protocol CAN, with a J1939 display label. This is metadata for that
named family, not proof of its runtime mapping to this AL5 or the selected
session. The record identities and attributes are retained privately.

Post-connect source `0x5D6D27..0x5D6DDE` assigns a local rate field +`0x72D7C`
from the selected protocol name: CAN=250000, IESCAN=500000,
1MEGCAN=1000000, J1708=9600 and XCP_ETHERNET=100000000; otherwise zero.
This field assignment is not a measurement of the physical bus or proof that
the loaded driver uses those settings. Connection code has vendor-specific
protocol rewrites and retries outside the new native model. In particular,
the common initialization includes a fallback from a BAUD=250 protocol string
to CAN after absolute client result `0x88`; the new model does not execute it.

The initial format-0 and ordinary format-1 headers remain per-message choices
using the same connection word. There is no evidence here of a VPW-to-CAN
transition. The working PcmHammer Mode `$23` VPW reader is unaffected; PCCS's
CAN-related host path is a separate investigation.

## Filter requests and remaining uncertainty

The installed `Noregon.Toolkit.RP1210.dll` provides a local primary naming
reference: static CLI metadata in `Noregon.Toolkit.SendCommands` binds
`SetAllFilterStatesToPass`=3, `SetAllFilterStatesToDiscard`=17 and
`SetMessageFilteringForCAN`=5. Assembly SHA-256 is
`a0cfa221b9b040d93bd612f87e6739a8876afd71691d22edda969b5dfd2288aa`.
This proves those enum names/values, not that every loaded driver implements
them successfully. No managed assembly is loaded or executed.

The identification filter replacement at `0x5D9E3F`, `0x5D9E9D` and
`0x5D9F01` sends command 17 with length zero, then two command-5 records of
nine bytes each. The branch at `0x5D9CA4` selects that region only for global
target F3. Target 3 instead jumps to request preparation `0x5D9F04`.

Similar filter replacements also occur in EnterWrite and other regions;
pass-all initialization must not be treated as permanent session state.
`emulate_pccs_filter_commands.py` models the identification target gate and,
with driver-name eligibility explicitly assumed, the native filter emitters.
It confirms these exact constructed records:

- First record: `00 000005F8 000005E8`.
- Second record for target 3: `01 0000F8FF 0000F803`.

Under a hypothetical type/BE32-mask/BE32-pattern interpretation with inclusive,
additive filters, the first admits initial reply ID 7EA and the second admits
ordinary reply ID 18EFF903: `7EA & 5F8 == 5E8` and
`18EFF903 & F8FF == F803`. This arithmetic supports the apparent intent to
retain both forms. The exact loaded driver's record interpretation,
additive behavior and active filter mode are not proven by these bytes or
enum names. The tool deliberately does not report installed/admitting filters.
Synthetic command errors also do not change host status within the bounded
emitter, so an immediate status-zero check would not resolve that uncertainty.
Their command results, filter mode, queue timing and actual driver behavior
remain separate from a source-level request. Complete programming and recovery
are still unproven.

## Offline evidence

New observations pin Winrw32.exe SHA-256
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.
Private source windows, export names and hashed XML metadata are in
`Tools/AL5/LocalOnly/PCCS_20261015/QuickWriteTrace/driver-connect-bindings-source.json`;
native observations are in `native-driver-connect.json`.
`rp1210-sdk-command-enum.json` preserves the static enum table observations;
`native-filter-commands.json` records seven filter contexts, including target
3 bypass, target F3, EnterWrite and synthetic command errors.
`filter-command-selection-source.json` and `FILTER_COMMAND_FINDINGS.md`
retain the filter emitters, surrounding guards and bounded callback inventory.
`initialization-sendcommand-literal-inventory.json` scans direct base-register
+`0x10` call encodings over `0x5D37A0..0x5D6C5B`, finding only `0x5D4C97`.
Computed aliases, SIB addressing and transitive callees are excluded; this is
not proof of permanent pass-all state through all initialization behavior.
The report retains explicit synthetic-callback and partial-execution fields.
Existing REA evidence is reused; these new observations use anchored source
bytes and bounded Unicorn 2.1.4 emulation, without provider metadata mutation.

Validation: **177 tests passed, no skips**, including ten new test methods,
with the pinned PCCS/DOC inputs and both S2 images present. Focused command
from `Tools/AL5`, with optional dependencies and `AL5_PCCS_EXE` configured:

```powershell
python -m unittest test_pccs_driver_connect test_pccs_filter_commands -q
```

No PCCS application entry point, driver DLL, Windows API, COM, adapter or
controller runs. Live-write gates remain unchanged. Reports retain
`live_write_enabled=false`, `ready_to_flash=false` and `would_send=[]`.

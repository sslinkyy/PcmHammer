# TJ1850 identification, reset and programming prerequisites

2026-10-15, continuation of `PCCS_J1850_PROGRAMMING_ROUTE.md`.
Bounded native checks now distinguish TJ1850 application/boot-marker reply
classification, reset ownership and parameter/security request construction.
They do not establish a continuous AL5 programming exchange or recovery. The
SPX1850 driver remains unavailable and live writes remain disabled.

## Probe reply classification

Probe helper `0x726514` constructs host buffer `01 68 6A F1 01 01` and uses
the driver's send/read callbacks. Its post-read branch requires signed reported
length greater than 7 and less than 128 before examining received fields.
New `emulate_pccs_j1850_identity.py` runs this reply branch only; it supplies
received fields and replaces a clock and identity-string assignment.

Synthetic buffer `00 00 00 00 48 6B 18 41` takes the application-response
branch, sets indexed family 1/version 0, assigns three spaces to the identity
field and sets host status zero. The source checks service 41 at this point
without verifying a subsequent PID/data byte. Acceptance of this minimal
synthetic buffer is therefore not validation of a real OBD response.

Synthetic buffer `00 00 00 00 6C F1 18 A2` takes the alternative branch,
assigns identity marker `BP `, family 1/version 0 and status zero. That branch
checks F1/18/A2; this does not prove a working bootloader or recovery mode.
The first four synthetic bytes are supplied receive fields, not an observed
SPX transport timestamp specification.

Other cases expose limits of the gate: source 19 with the application header
can set family 3/status zero before reaching the clock/retry boundary; a wrong
service, length 7 and length 128 do not enter the accepted paths. These are
interior reply-parser results, not full probe completion or timeout/retry
qualification. The six native contexts preserve QuickWrite and alternate bytes
because this particular parser slice does not write them.

## Reset prefix and global ownership

The actual TJ1850 reset prefix `0x726734..0x726760` clears the local object's
+72D90 alternate byte. Its byte-counter loop then clears 256 indexed +B4
flags through the object pointed to by global `0x81F328`. That pointer is an
important owner: it need not equal the receiver object in an arbitrary state.

Six new native reset contexts vary prior QuickWrite byte 0/1/255 and whether
the global object aliases the local receiver. They execute the complete prefix
loop and stop before helper `0x726514`. In the separate-object cases, global
owner flags clear while local indexed flags stay unchanged. Neither object's
QuickWrite byte +68C60 is cleared by this prefix. This differs from the base
reset's immediate QuickWrite clear, but does not establish that the full
TJ1850 reset or its callees always preserve QuickWrite.

Static source after the probe checks status, family and identity marker.
The `BP ` marker can bypass the later metadata reads. Otherwise the branch
requests identifiers 1A40, 1A4A, 1A68, 1A69 and 1A6A through VMT +48, checking
status between stages. The later success stores include family 1/version 0,
indexed +B4=1 and metadata fields +74=8000 / +78=18000. These field values
are not an authorized erase range or proof that all memory in it is safe to
rewrite. A subsequent read at 8000 can still change family to 3 on error.

## Parameter reads and security construction

VMT +48 resolves to `0x7252B8`. Its constructor places `22 <identifier BE16>
01` in the internal request buffer, sets request length 4 and reply-prefix
length 3, and dispatches to supplied target 18 with EDX 4/timeout parameter
1200. On status zero, later source copies the caller-requested byte count from
response +5267B. Dispatcher acceptance and returned data remain prerequisites.

New `emulate_pccs_j1850_prerequisites.py` runs independent request constructors
for those five identifiers and for seed/key helpers. It stops before every
send or virtual dispatch. Nine contexts construct:

- Seed host buffer: `01 8C 18 F1 27 01`.
- Key host buffer: `01 8C 18 F1 27 02 <key BE16>`.
- Parameter payloads: `22 1A 40 01` through the listed identifiers above.

Seed storage +29C and key storage +29E coincide with indexed +B0/+B2 when
the selected index is 3. The key words in the native constructor tests are
synthetic; no seed/key algorithm or security authorization executes.

Static RequestSeed checks include a length-13 reply with service 67/01 and
seed bytes +528B9/+528BA. A length-10 67/01/37 branch, when local BL is zero,
requests a 12000 delay, sets BL and retries. A later 37 can produce status F,
but other send-error branches can loop with BL set. This is not a proven
bounded overall retry policy, and transfer/security retry is not recovery.
No delay or send/receive callback was executed by these checks.

The shared EnterWrite body calls the virtual RequestSeed/SendKey slots.
Its key producer depends on flags, controller version and resource paths:
source can use `0x5B7A70`, DELPHISEEDKEY, SEEDKEYG4 or SEEDKEY tables, with
a special FFFF case. The selected AL5 key producer and its complete algorithm
have not been established by this pass. The prior working reader's independent
seed/key findings do not fill in these PCCS branches automatically.

## Offline evidence and limits

Source is pinned Winrw32.exe SHA-256
`13e083b9f1fc31b0909614c1403e9fb007f48385f0035c4f2725ffc525e6d40d`.
These observations use anchored original bytes and bounded Unicorn 2.1.4
emulation, retaining prior REA evidence without a new provider-completeness
claim. No function metadata was changed.

Validation: **214 tests passed, no skips**, including eleven new test methods,
with pinned PCCS/DOC/SoftUSB/Vector inputs and both S2 images present. Focused
command from `Tools/AL5`, with optional Unicorn and `AL5_PCCS_EXE` configured:

```powershell
python -m unittest test_pccs_j1850_identity test_pccs_j1850_prerequisites -q
```

Private evidence in `Tools/AL5/LocalOnly/PCCS_20261015/QuickWriteTrace/`:
`pccs-j1850-identity-source.json`, `native-j1850-identity.json`,
`pccs-j1850-prerequisites-source.json`,
`pccs-j1850-prerequisites-native.json` and
`PCCS_J1850_PREREQUISITES_FINDINGS.md`. Native stages are independent and
reports preserve synthetic callbacks, omitted execution and qualification
limits. No PCCS entry point, DLL, Windows transport API, COM, adapter or
controller ran. Mode `$23` reading is unchanged. All live-write gates remain
closed; reports keep `ready_to_flash=false` and `would_send=[]`.

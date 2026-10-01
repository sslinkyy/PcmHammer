# Application descriptor and security guard — offline evidence

Twenty isolated firmware cases now exercise descriptor dispatch, the saved
fixed-selector seed/key handler, its boot-request guard and failure state.
`APPLICATION_AUTHORIZATION_EMULATION.json` records hashes, synthetic inputs,
assertions and observations. No live seed/key, session, reset or write was sent.

## Descriptor processing is a direct callback

The extracted processor at 0xB1970–0xB1B23 interprets the first descriptor byte
bit four as a callback-present flag. For the saved 0x9000 descriptor at 0x99A30,
it invokes the pointer at descriptor+2, namely 0xBE6D0, with request pointer
0xFF8EB6 plus the byte offset at A5+0xEFF. Its tested call argument one reaches
that callback for state byte A5+0xF2A equal to zero, one, two or three. The
service dispatcher at 0xA4C20 supplies that argument.

Argument zero does not call this handler in tested states one/two; removing
descriptor bit four also prevents the callback. These are negative synthetic
tests, not proposed descriptor edits. The remaining descriptor bits and their
roles for other services are not fully interpreted. In particular, the first
byte's 0x80 is not established as security authorization by this callback test.
This routine is not evidence of a queued scheduler for the saved 0x34 path.
Full receive processing and selection of state/offset remain unverified.

## Corrected helper interpretation

The earlier harness logged the stub at 0xA9D8C as `response_helper_calls` without
claiming a wire response. Its extracted instructions show a memory-clear
operation: clear ceil(argument/8) bytes at the supplied pointer. Argument 0x55
clears exactly eleven bytes at A5+0xF36. New observations use
`memory_clear_helper_calls` and execute the real helper. The thirteen-byte
sentinel test confirms eleven zero bytes followed by two unchanged bytes.

It does not transmit a response. Application response construction and the
separate helper at 0x5BAB8 remain outside the experiment. Historical reports
retain their original labels/hashes; their former stub results are not upgraded
to real helper execution.

## Security guard and saved selector

The application service 0x27 descriptor points to 0x9820C. Under the saved
selector byte zero at 0x10954, the locked seed-request path loads the fixed
seed 0x9CE5 from 0x3FD8 and sets bit six of A5+0x1DBE. A matching fixed key
0xBC08 from 0x3FDA clears bit five (and bit seven); the next descriptor callback
then passes the boot handler's bit-five guard. The linked seed/key/callback
sequence retains actual synthetic RAM state between calls.

Bit five therefore acts as a security-lock guard in these extracted paths.
Unlocked seed requests stage seed zero. A locked key request without bit six
calls the negative helper with argument 0x22. A matching key with the tested
nonzero lockout counter is rejected through the staged result path.

Two wrong-key attempts, with an actual extracted seed request between them,
produce staged results 0x35 then 0x36. The first sets bit seven and clears bit
six. The second clears bits six/seven, leaves the lock guard set, writes counter
100 at A5+0x1DC0 and sets a neighboring flag at A5+0x1DC2. The decrement rate,
counter initialization and persistence are not traced; **100 is not a duration
in seconds**. Timer expiry, power-cycle clearing and lockout recovery are open.

These results are internal staged records at A5+0x1DBA, not captured physical
wire responses. A two-byte result can retain a stale third byte from the prior
seed. For example raw record `02 02 36 E5` has declared payload `02 36`;
the trailing E5 must be excluded. Tests enforce declared-length parsing.

## Fixed pair versus dynamic transform

The earlier observed pair 0x9CE5/0xBC08 matched an algorithm-50 hypothesis, but
the saved application's selector-zero path uses literal seed/key words. That
pair alone cannot identify the active transform. The separate extracted
routine at 0x85438, used by selector-one branches, rotates the seed by four
bits, XORs five table selections and constant 0x3B0A. In isolated execution,
input 0x9CE5 produces low word **0xACE1**, not 0xBC08. The saved selector stays
zero in the stateful security experiments; no selector-one seed hardware is
emulated. No production security algorithm or key sender was added.

## Scope and continuation

`emulate_application_authorization.py` extends the existing isolated
application harness, retaining known source hashes, read-only ROM, strict
execution ranges, trapped reset loops and absent flash code. Descriptor and
guard state are synthetic. Sensor helper 0xBD89C, negative-response delivery,
cleanup and physical reset remain stubbed or trapped. The shared harness was
also rerun against its original twelve cases after the extension.

The dry-run planner links this evidence by hash; live key submission and lockout
duration remain explicitly unverified. Live-session authorization, application
entry verification and write readiness remain false; packet lists stay empty.

The subsequent `RECEIVE_PREPARATION.md` executes the selected classifier and
0x5BAB8 caller while intercepting all storage/subsystem implementations. Boot
preparation reaches persistent flash-update calls outside calibration. Next
resolve the receive-buffer lifecycle, storage recovery and reset/boot timing. Exact flash geometry, loader ABI, preservation, programming
wire path and recovery remain unresolved. The direct reader is unchanged.

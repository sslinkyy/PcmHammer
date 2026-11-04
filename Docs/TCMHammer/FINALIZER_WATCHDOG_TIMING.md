# Finalizer watchdog service and verification timing

This is offline code-path evidence. The spare remains in transit. No device access, live upload, execution, erase, programming or physical reset is enabled. Instruction counts are not elapsed-time measurements.

## New native trace

The earlier finalizer model stopped at the retained marker or park path with a watchdog RTS stub. `trace_loader_watchdog_tail.py` instead executes the captured loader's real sender, watchdog helper, two delay loops, retained-RAM store and a bounded number of park branches in one emulator context. No instruction bytes are patched. Every peripheral instruction is intercepted before access; modeled MOVE condition codes preserve the CPU flow. The two RAM views share the declared 24-bit alias, so the original marker-store instruction executes against emulated RAM at effective `0xFFFF8000`/`0xFF8000`.

The trace starts at the selected success-status, bad-sum-status, shared-exit or last idle-iteration boundary. It does not repeat final checksum calculation, flash marker programming, full receive scheduling or boot-to-loader handoff. Existing finalizer/marker tests establish those separate bounded paths; this tool does not promote them into one continuous physical session.

## Service-to-park behavior

The native helper at `0xFF960C` writes byte `55`, then byte `AA`, to absolute-short `FA27`, effective `0xFFFFFA27`. Each delay sets D5 to `B000`, services through that helper, increments D5 and loops until `FFFF`. Each therefore reaches exactly 20,479 ordered service pairs in this context. Both delays service the watchdog; they are not a delay spent starving it.

With immediately ready synthetic sender status, the complete success tail produces software FIFO bytes `6C F0 18 76 00 86`, six sender service pairs and 40,958 delay pairs: 40,964 pairs total. The bad-sum tail constructs status `FF` and reaches the same exit/park path. Interface writes `40` to `0xFFFFE800` and `00` to `0xFFFFE801` remain suppressed. After the second delay, native code writes retained RAM marker `D0C2`, then self-branches at `0xFF9250`. No further watchdog service, receive-loop entry or RESET opcode occurs in the bounded park continuation. The shared exit and selected last idle iteration reach the same tail without constructing a status frame.

This supports watchdog starvation as a **conditional inference** after park, if the effective watchdog configuration is enabled and applicable. It does not demonstrate a hardware reset, timer duration, retained-memory survival, complete wire delivery, or controller readiness for another request.

## Sender timeout is a software restart branch

The sender repeatedly services the watchdog while polling its synthetic busy input. Permanent busy status reaches a jump to loader entry `0xFF9000` after 4,096 service pairs and 4,095 status reads. That trace stops before executing the restarted entry. Only the first FIFO byte has been submitted in the model; neither final marker storage nor park is reached. The boundary case with 4,094 busy reads succeeds, while 4,095 busy reads exhaust the countdown before the next status read.

A software jump back to loader entry is separate from a watchdog reset. A partial status or missing final reply cannot authorize another destructive request. Existing uncertain-send, timeout and retry-review ownership is unchanged.

## Conditional manufacturer interpretation

The [NXP MC68336/376 register summary](https://www.nxp.com/docs/en/user-guide/MC68336376UMD.pdf), D.2.15, describes the software-service register at `YFFA27` and the ordered `55`/`AA` sequence. D.2.12 describes watchdog enable/prescale/timing and a control register writable once after reset. The earlier pinned boot store at `0x48E` writes `84` to `0xFFFFFA21`; see [the existing application/boot chain](WRITE_QUALIFICATION_PLAN.md).

Those observations fit a conditional CPU-family interpretation. The actual AL5 MCU, effective application-time control value, source clock, peripheral timing and reset behavior remain unqualified. Do not convert the delay iteration count or an assumed CPU clock into an asserted physical verification window. Neither the RAM marker nor interrupt masking is itself a hardware reset command.

## PcmHammer progress reporting

The rehearsal, candidate, dispatcher and internal execution report now retain `SavedFinalizationReplyObserved` separately from `SavedCleanupObserved`. The first becomes true only after the matching success reply in its owned finalization slot. It remains true if a later cleanup step stops. A submitted request, error status `FF`/`F8`, or partial send does not set it.

Execution reports explicitly keep `PhysicalResetVerified`, `PostFinalizationReadbackWindowVerified` and `PhysicalDeadlinesQualified` false. The caller-selected time budgets remain model budgets. Success status alone still cannot invoke full saved readback verification before cleanup; a later terminal stop remains terminal. The native paths do not prove that the loader can service a host read between status and park, nor does a saved cleanup exchange establish the physical reset epoch.

The strict full-image/bank comparator and [startup-bank diagnosis](STARTUP_BANK_VERIFICATION.md) remain unchanged. Physical qualification must distinguish final-status observation, peripheral completion, last watchdog service, actual reset/application restart, and the independently acquired readback epoch. None of these missing physical observations is filled by a fixed sleep or a packet-count assumption.

## Reproduction and validation

```text
python Tools/AL5/trace_loader_watchdog_tail.py --loader captured_efi_loader.bin --output NEW-report.json
python Tools/AL5/test_loader_watchdog_tail.py --loader captured_efi_loader.bin
```

The report pins the 1,590-byte captured loader SHA256, generator hash and selected input path. Eight native cases cover success, bad sum, delayed/permanently busy sender, both countdown edges, shared exit and selected idle expiry. Tests check exact service ordering/counts, unchanged loader bytes, RAM alias storage, stable stack, absence of service during bounded park, lack of RESET/receive execution, and input rejection before emulator creation. Scripted writer tests additionally retain the separate finalization/cleanup evidence and reject premature verification and error-status promotion.

The [metadata-only native report](../AL5/LOADER_WATCHDOG_TAIL_EMULATION.json) retains source/input hashes, ordered software event positions, service counts and explicit false physical/live flags. Raw loader bytes remain local/private. The final application library is exercised by 63 scripted execution cases, including the first-cleanup-send failure after a success reply; no physical test ran.

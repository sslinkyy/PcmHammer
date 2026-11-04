# Inherited watchdog configuration and post-reset checks

All work remains offline while the spare is in transit. No hardware discovery, live upload, execution, programming or reset is performed. Native code runs only in the existing M68K emulator with the pinned historical image, declared address aliases and synthetic peripheral/reset inputs.

## Configuration observations

The bounded reset-to-application trace now retains the same CPU and RAM through native boot, application entry and the first calibration-check return or rejection. The observed byte write at boot PC `0x48E` targets `0xFFFFFA21` with value `84`. Application initialization later attempts the same value at `0xC5C3C`. The [NXP MC68336/376 summary](https://www.nxp.com/docs/en/user-guide/MC68336376UMD.pdf), D.2.12, defines a write-once protection-control register at that address. Under this conditional interpretation, the first write establishes the setting and the application attempt does not replace it.

The explicit observer keeps an unknown or already-latched configuration distinct from a fresh-reset hypothesis. A native write attempt does not establish its effective value when the first write was already consumed. For the `84` hypothesis, decoded watchdog enable/prescale/timing fields select a period of 512 system-clock cycles. The actual MCU, effective register and source clock remain unverified; the observer never supplies a frequency or timeout in seconds. Disabled/unknown and alternate prescale/timing controls are tested separately.

## Same-context native copy to loader entry

A second bounded path starts at the native reset vector with synthetic retained marker `BFC1` and reset status `20`. It follows boot initialization, the existing scripted arm exchange and the native RAM-copy/JSR path for the exact captured 1,590-byte EFILive loader at `0xFF9000`. Reset, arm exchange and loader copy share one CPU/RAM context; there is no reset-to-upload snapshot join. The source bytes are not preloaded into RAM. Native byte-copy coverage, pinned digest, stack delta `-72` and pending return `0x33B8` are checked before stopping at the loader entry boundary.

The only observed watchdog-control attempt on that path is boot's `84`. Therefore the conditional latched setting remains unchanged up to the first loader instruction. The new operation is one-shot and accepts only the pinned captured loader. It cannot adopt a compiled read-only runtime, retry a failed copy, run arbitrary code or enter the writer's erase/program implementation. The existing compiled-reader copy still has its separate layout and runtime-ownership checks.

This is an emulator trace, not an actual interrupt, upload or reset. The retained programming marker and FIFO/IRQ events remain synthetic. The loader's later service/delay/park behavior is documented in [the watchdog tail trace](FINALIZER_WATCHDOG_TIMING.md); a measured hardware deadline is still absent.

## Post-reset verification coverage

Eight bounded reset cases cover retained-marker watchdog, power and external reset-status hypotheses; damaged calibration CRC; changed compensation word; absent calibration marker; lost retained marker; and the existing bounded OS checksum/address-alias fault.

With `D0C2` retained, native boot validates the saved OS, records `2FE6`, and transfers to the application. Native initialization then reaches the calibration check. The ordinary good path returns at `0x994FE`, before later startup and persistent-storage activity. Invalid calibration CRC and missing calibration completion marker are rejected by the application even though the boot OS checks pass. Losing `D0C2` under the tested watchdog-status hypothesis stops at the boot failure boundary. The OS-fault case reaches the existing native boot idle path without entering the application. None of these endpoints establishes physical recovery or host communication readiness.

The application reads `0x8000..0x15FD5` inclusive: 57,302 unique calibration bytes. It also reads the calibration completion marker at `0x1FFFE`. The final compensation word at `0x15FD6..0x15FD7` is outside this examined application-check coverage. An exact one-byte compensation change still returns from the native application check. Consequently, application acceptance cannot replace full-image, collateral, bank or compensation verification.

The boot-side application marker at `0xFFFFE` and the calibration marker at `0x1FFFE` are separate locations. Neither is the retained RAM word at `0xFF8000`. Reset routing, OS validation, application calibration CRC, loader checksum and independently acquired preservation comparison remain distinct evidence.

## Offline writer regressions

The scripted writer harness now consumes the native report with exact reference and resulting full-image SHA256 binding. It rehearses unchanged calibration through cleanup, then compares the saved native fixtures using the production candidate. The good control matches; changed CRC, compensation and completion marker stop strict verification. In particular, the native-accepted compensation fixture still fails PcmHammer's full saved-image comparison. Saved file equality remains distinct from physical readback qualification.

The existing journal tests use the same prepared-candidate rehearsal helper. There is no new exception to bank preservation, no promotion of post-reset checks to an original backup, and no physical-reset/readback-window flag is enabled.

## Reproduction

```text
python Tools/AL5/trace_watchdog_inheritance.py --full-reference FULL-reference.bin --loader captured_efi_loader.bin --output NEW-report.json
python Tools/AL5/test_watchdog_inheritance.py --full-reference FULL-reference.bin --loader captured_efi_loader.bin
```

The native report preserves selected paths and reference, loader and implementation digests. The model validates the original saved firmware before applying only the explicit calibration/marker test overlays. Post-reset continuation is opt-in; ordinary boot/read-only-runtime behavior keeps its earlier boundaries. Unknown/uncompleted application peripheral reads stop rather than silently receiving a success value; prior boot and register-readback assumptions remain conditional.

The execution test harness accepts `--post-reset-report REPORT` alongside its existing `--journal-report REPORT` option after `--receipt NEW_JSON`. These are file-only evidence inputs. Live upload, execution and writes remain disabled; actual watchdog configuration, marker retention, reset timing, coherent independent readback and spare restoration remain qualification gates.

The [metadata-only native report](../AL5/WATCHDOG_INHERITANCE_POST_RESET.json) retains input/source identities and all eight reset/check cases plus the owned native-copy handoff. Six new native/configuration test methods, the existing reset-reader regressions, and 67 scripted writer cases pass. The production application inputs remain byte-identical to the previously sealed disabled build. No hardware qualification was run.

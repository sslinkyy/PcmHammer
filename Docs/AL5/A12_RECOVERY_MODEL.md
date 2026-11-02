# AL5 temporary flash-fault recovery model

Offline evidence only. Live upload, execution and writes remain disabled; physical recovery is unverified.

## Pin and address mapping

AMD/Spansion Am29F800B datasheet 21504E5, 44-pin SO connection diagram: A12 is pin 38; pin 27 is DQ13. Package and board routing must still be established for the actual module. Source: https://www.batronix.com/files/Datenblaetter/29__/AM29F800B.pdf (PDF page 7).

The pinned SPS loader uses word command addresses at CPU byte addresses 0xAAA and 0x554, consistent with flash word addresses 0x555 and 0x2AA. This supports the candidate chip-A12-to-CPU-byte-bit-13 mapping, but does not prove high-line continuity. The primary fault view reads every byte from address & ~0x2000, periodically throughout the image. A CPU-bit-12 alternative and a big-endian x16 DQ13 control are separate unverified hypotheses.

## Reset continuity and outcomes

`Tools/AL5/emulate_flash_fault_recovery.py` starts at the saved reset vectors (SSP FFFF8FFE, PC 400). Both instruction fetch and data see the selected fault view. Translation caches are invalidated on view changes. Changed instruction spans stop before altered instruction semantics are executed.

- Normal mapping: boot and OS checksums are zero; execution reaches the application boundary.
- A12 held low from reset: boot checksum becomes 0531; execution reaches boot-failure wait 96E before VPW initialization.
- Normal through the boot self-check, fault activated at 806 and released at OS rejection 890: OS checksum becomes 2979. Native initialization reaches the boot idle loop with interrupts unmasked.
- In that same reset/RAM session, a synthetic ISR entry with scripted request 6D18F034 produces software TX bytes 6DF0187444 and upload-arming byte 1. Execution stops before RTE; no upload is attempted.
- Keeping the fault active until the VPW initializer is too late in this model: initialization first encounters changed instruction bytes at 2C90.
- DQ13 held from reset changes the first instruction at 400; this is a data-line control, not an A12 result.
- A modeled external service signature 5AA5 transfers outside the declared executable context; that branch is not simulated by a fake return.

Independent inclusive BE16 sums of 0..3F06 and 20000..C5F92 reproduce the native zero/0531/2979 results. The completion marker at 1FFFE aliases to another 4AFC value: marker corruption is not the modeled trigger.

## Explicit limitations

The historical saved image is not a current full physical backup. The M68020 emulator, shared 24-bit RAM/module aliases, reset/status inputs, absent external service, FIFO events and synthetic interrupt entry are assumptions. Software TX observations are not measured wire traffic. No real IRQ, exception return, flash operation, electrical timing, current contention, watchdog timing or physical recovery was qualified. The software-PC boundaries are not actionable pulse timings or connection instructions.

The conditional result justifies further offline tracing; it does not establish a practical A12 recovery method. High address-line routing, actual reset behavior and a recoverable test module remain unresolved.

## Reproduction

Use task-local Capstone and Unicorn dependencies. Run `test_flash_fault_recovery.py --low LOW --high HIGH --loader LOADER` with the pinned historical inputs; source size and SHA-256 are checked. Run `emulate_flash_fault_recovery.py` with the same inputs and `--output NEW_JSON` to retain the core ten-case report and eight reset-status comparisons. Proprietary firmware and detailed reports remain under LocalOnly/private storage.

## Reset-status sensitivity

The expanded model takes an explicit synthetic FF FA07 status byte. With 00 and the original synthetic zero retained marker, both the normal and proposed alias window stop at boot-failure wait without activating the fault. With 40, 80 or C0, normal mapping reaches the application boundary and the OS-check alias/release reaches the same synthetic boot-request acknowledgement. Thus the original 80 assumption is material for a zero retained marker: either bit 6 or bit 7 selects the integrity-check route. It is not a universal requirement; the retained-marker cases below establish other native branches. Actual register identity, reset cause and physical power-on values remain unverified. This is a software input comparison, not a hardware reset test.

## Native retained-marker routing and conditional reset causes

The [NXP MC68336/376 register summary](https://www.nxp.com/docs/en/user-guide/MC68336376UMD.pdf), D.2.4 (PDF pages 8-9), assigns RSR to YFFA07: bit 7 EXT, bit 6 POW, bit 5 SW, bit 4 HLT and bit 1 SYS. RSR is updated on reset and ignores writes in that family. This matches the saved address/test pattern conditionally; it does not identify the actual AL5 MCU. The offline model rejects attempted status-register writes rather than inventing new reset causes.

Native code at 4E6 saves the retained FF8000 word in D4 before destructive RAM tests; 7C2 restores it. The boot checksum runs afterward. At 7EA and 7F2, either high reset-status bit selects 806. If both are clear, comparison at 7FA still selects 806 for retained D0C2. Thus the A12 alias/release experiment can reach the same B615 boot path with status 00 and retained D0C2. Without the alias, that case passes OS verification and reaches the application boundary instead.

With status 00 and normal flash addressing, recognized retained markers follow these native outcomes:

- 6124 -> 23CB, BFC1 -> B094, 30D4 -> 3E91, 8C9B -> A8E1, A004 -> B615, CC8B -> C7D8 and 9515 -> C12A: reach boot initialization and the synthetic Mode 34 acknowledgement.
- 9372 and unrecognized zero: boot-failure wait.
- 0595 and 2FE6: application-resume branch, with resulting marker 0595.
- D0C2: OS verification then application transfer if the saved image passes.

BFC1 produces software TX frame 6CF0187444 during native startup and 6DF0187444 during the later synthetic interrupt/request. Reports now retain phase attribution. They do not attribute either to a real wire capture. At A82, native startup copies the word spanning FFFA06/07 to FF8008; the report records this synthetic status snapshot. The upper byte at FFFA06 is modeled as zero, not assigned real hardware semantics.

`audit_a12_reset_routing.py --low LOW --high HIGH --output NEW_JSON` records pinned static windows and twenty native experiments. `test_a12_reset_routing.py --low LOW --high HIGH` checks saved/restored markers, status read sites, routing, TX phases, input rejection and offline gates. Status 02/10/20 comparisons preserve the same D0C2 and 2FE6 routes when bits 6/7 are clear. These selected cases and static branches are not an exhaustive reset/peripheral model.

Retaining a marker is an explicit synthetic input. No experiment demonstrates that it survives loss of power, how a particular watchdog/reset occurs, or that any software parking loop resets this physical controller. Existing marker producers and the application boot-request analysis remain in [Application boot entry](APPLICATION_BOOT_ENTRY.md). A software path into boot handling and a physical recovery method are separate validation gates.

# AL5 public-source research, 2026-10-06

Target: user-reported hardware 15183963, OS 15184109, calibration 15183960.
Internet research only; no hardware commands, downloads of executable software,
support messages or live programming. Sources describe different confidence
levels and must not silently open physical verification gates.

## Manufacturer and tool-vendor documentation

[EFILive TCM support](https://www.efilive.com/tcm-tuning) identifies AL5 as the
2001–2005 Allison five-speed controller, separately from later A40/A50 units.
This supports the generation match; it does not identify the processor or flash.

[EFILive V8 Reference](https://download.efilive.com/Documentation/EFILive%20V8%20Reference.pdf),
flashing section around printed page 74, describes unlocking, network silencing,
proprietary loader download where needed, erase and reprogramming. Its test-flash
option transfers data without erase/program; full flashing changes OS and
calibration, while calibration flashing changes calibration. The manual warns
against interrupted full flashes on AL5 and other older controllers.

Implication: the documented loader architecture agrees with our captured-loader
analysis. Test flash is a useful future research lead, not permission to run it.
Availability for this exact AL5/software/device combination remains unverified.
Our saved firmware evidence includes persistent-bank writes during preparation;
therefore “no erase/program” in a generic tool description must not be treated
as proof that all session entry/cleanup is free of persistent side effects.
Neither this option nor its name establishes recovery, real erase success,
voltage suitability, complete capture or correctness of our custom kernel.

[EFILive Controller Recovery Process](https://service.efilive.com/kb/articles/controller-recovery-process),
updated July 2021, specifically groups AL5 with LS1/LB7/LLY. It distinguishes
calibration-flash failures, described as generally recoverable, from full-flash
failures. Recovery after power loss depends on restored communication code;
the article describes physical flash removal/reprogramming/replacement for
noncommunicating failures. AutoCal stock-file flashing also requires permission
through its remote license.

Implication: a manufacturer's documented recovery procedure is stronger than
generic forum advice, but does not demonstrate recovery for the user's unit.
Do not assume SPS2 or a generic forced-boot/key-timing trick restores a blank or
damaged boot region. Calibration-only failure guidance does not validate our
unproven custom erase scope. No recovery experiment is authorized here.

[Allison service tools and information](https://www.allisontransmission.com/aftermarket-and-channel/parts-and-service/service-tools--information)
points to Allison HUB/ePubs for official maintenance/troubleshooting publications,
Allison DOC for diagnostics/configuration work and TCM Reflash for replacement
module calibrations. This broad product-family page does not establish that a
particular tool/version, interface or recovery function supports this GM AL5.

## Hardware leads and generation mismatches

A [2020 first-person reverse-engineering post](https://pcmhacking.net/forums/viewtopic.php?p=102000)
reports suspected 29F800/1 MiB flash in an Allison controller and possible
boot-mode behavior. It is a useful independent search lead, not a photographed
chip identification, published pinout or reproducible recovery procedure.
It does not bind an exact hardware number. Our own loader ID/command/geometry
evidence remains the stronger conditional flash-family argument.

The [Allison fourth-generation teardown](https://www.duramaxdiesels.com/forum/threads/whats-inside-allison-4th-gen-tcm.41993/)
is first-person board photography of a later controller. It cannot establish
the board construction, potting, processor or debug pads of the user's AL5.
Do not transfer later-generation pinouts or opening methods to this unit.

Public listings associate hardware 15183963 with the five-speed generation and
often advertise numbers 29537441/15768288. Seller interchange labels are not
manufacturer compatibility proof or a substitute for the actual module label.
No purchase or replacement selection is made from those listings.

## Remaining public-source gaps

The searches did not yield a verified schematic, exact MCU marking, BDM/JTAG
pad map, flash-chip photograph bound to hardware 15183963, or a complete open
AL5 programming protocol. This is a search result, not proof that none exists.
No reviewed primary source demonstrated SPS2 recovery or the proposed WINRW32
key-off/key-on trick for this exact unit. General/heavy-duty Allison and later
generation examples cannot resolve that claim.

Useful next evidence remains actual label/board/chip photographs, read-only
session observations, independently decoded saved traces and reproducible
hardware recovery evidence. Preserve the working Mode 0x23 reader and all
closed write gates. This research supplements the existing project; it does
not replace its mappings, raw images or prior offline reconstruction.

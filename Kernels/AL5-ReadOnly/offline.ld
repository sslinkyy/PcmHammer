/* SPDX-License-Identifier: GPL-3.0-only */
ENTRY(al5_ro_entry)
SECTIONS {
    . = 0xFF9006;
    .text 0xFF9006 : { KEEP(*(.text.entry)) *(.text*) *(.rodata*) }
    .data : { *(.data*) }
    .bss : { *(.bss*) *(COMMON) }
    /DISCARD/ : { *(.comment*) *(.note*) }
    ASSERT(SIZEOF(.data) == 0, "Unexpected writable initialized data")
    ASSERT(SIZEOF(.bss) == 0, "Unexpected implicit state")
    ASSERT(ADDR(.text) + SIZEOF(.text) <= 0xFFA000, "Kernel overlaps reserved RAM")
}

/* SPDX-License-Identifier: GPL-3.0-only */
.section .text.entry,"ax"
.balign 2
.globl al5_ro_entry
.type al5_ro_entry,@function
al5_ro_entry:
    move.w #0x2700,%sr
    move.l #0x00FFA7FE,%sp
    jsr al5_ro_init
1:
    jsr al5_ro_step
    bra.s 1b
.size al5_ro_entry,.-al5_ro_entry
.section .note.GNU-stack,"",@progbits

/* Clean-room opcode verification only; not PCM Hammer product code. */
    .text
    .globl _start
_start:
    movea.l #0x00FFA7FE, %a7
    jsr     0x0005F140
    jmp     0x0002180C

entry_b:
    movea.l #0x00FFA7FE, %a7
    jsr     0x0005F140
    jmp     0x00021922

common:
    move.w  %sr, -(%a7)
    move.l  #0x494D4248, 0x00FF88B0
    move.l  #0x00000001, 0x00FF88B4
    move.l  #0xFFFFFFFE, 0x00FF88B8
    move.l  #0x48423031, 0x00FF88BC
    move.w  (%a7)+, %sr
    rts

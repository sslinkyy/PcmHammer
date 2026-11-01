/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef AL5_READ_CORE_H
#define AL5_READ_CORE_H
#define AL5_RO_REQUEST_BYTES 22u
#define AL5_RO_MAX_DATA 32u
#define AL5_RO_MAX_REPLY 54u
/* Candidate scratch addresses for emulator ABI only; physical RAM ownership is unqualified. */
#define AL5_RO_REQUEST_RAM 0xFFA500ul
#define AL5_RO_REPLY_RAM 0xFFA600ul
/* Callable offline prototype only. No entry loop, adapter integration or flash writer. */
unsigned int al5_ro_read(const unsigned char *request, unsigned int length, unsigned char *reply, unsigned int capacity);
#endif

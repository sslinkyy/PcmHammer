/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef AL5_READ_RUNTIME_H
#define AL5_READ_RUNTIME_H
#define AL5_RO_STATE_RAM 0xFFA300ul
#define AL5_RO_STATE_BYTES 20u
#define AL5_RO_RX_RAM 0xFFA380ul
#define AL5_RO_TX_RAM 0xFFA400ul
#define AL5_RO_RX_BYTES 26u
#define AL5_RO_TX_BYTES 58u
/* Experimental VPW envelope only; no live adapter support or assigned standard service. */
#define AL5_RO_REQUEST_SERVICE 0xB1u
#define AL5_RO_REPLY_SERVICE 0xF1u
void al5_ro_init(void);
/* Local offline entry point only; no wire service or live invocation is provided. */
void al5_ro_request_quiesce(void);
unsigned int al5_ro_step(void);
#endif

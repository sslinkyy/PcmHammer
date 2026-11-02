/* SPDX-License-Identifier: GPL-3.0-only */
#include "read_core.h"
#include "runtime.h"
#define STATUS (*(volatile unsigned char *)0xFFE800ul)
#define COMMAND (*(volatile unsigned char *)0xFFE800ul)
#define DATA (*(volatile unsigned char *)0xFFE801ul)
#define WATCHDOG (*(volatile unsigned short *)0xFFFA26ul)
struct ro_state {
    unsigned short rx_count;
    unsigned char discard;
    unsigned char tx_active;
    unsigned short tx_count;
    unsigned short tx_index;
    unsigned long polls;
    unsigned long watchdog_pairs;
    unsigned char lifecycle; /* 0 running, 1 draining software, 2 software parked */
    unsigned char reserved[3];
};
typedef char state_must_match_layout[(sizeof(struct ro_state)==AL5_RO_STATE_BYTES)?1:-1];
#define STATE ((volatile struct ro_state *)AL5_RO_STATE_RAM)
#define RX ((volatile unsigned char *)AL5_RO_RX_RAM)
#define TX ((volatile unsigned char *)AL5_RO_TX_RAM)
#define REQUEST ((unsigned char *)AL5_RO_REQUEST_RAM)
#define REPLY ((unsigned char *)AL5_RO_REPLY_RAM)
static void kick_watchdog(void) {WATCHDOG=0x0055u;WATCHDOG=0x00AAu;STATE->watchdog_pairs++;}
void al5_ro_init(void)
{
    unsigned int i;
    volatile unsigned char *s=(volatile unsigned char *)AL5_RO_STATE_RAM;
    for(i=0;i<AL5_RO_STATE_BYTES;i++)s[i]=0;
    for(i=0;i<AL5_RO_RX_BYTES;i++)RX[i]=0;
    for(i=0;i<AL5_RO_TX_BYTES;i++)TX[i]=0;
    for(i=0;i<AL5_RO_REQUEST_BYTES;i++)REQUEST[i]=0;
    for(i=0;i<AL5_RO_MAX_REPLY;i++)REPLY[i]=0;
    kick_watchdog();
}
void al5_ro_request_quiesce(void)
{
    if(STATE->lifecycle==0u) {
        STATE->lifecycle=1u;
        if(STATE->rx_count!=0u)STATE->discard=1u;
    }
}
/* One bounded step. Numeric FIFO classes mirror observed loader branches, not qualified physical semantics. */
unsigned int al5_ro_step(void)
{
    unsigned char status,kind,value;
    unsigned int i,n;
    kick_watchdog();STATE->polls++;
    if(STATE->lifecycle>2u || STATE->tx_active>1u || STATE->discard>1u || STATE->rx_count>AL5_RO_RX_BYTES ||
       STATE->tx_count>AL5_RO_TX_BYTES || STATE->tx_index>STATE->tx_count ||
       (STATE->lifecycle==2u && (STATE->tx_active || STATE->rx_count || STATE->discard)) ||
       (STATE->tx_active && (STATE->tx_count==0u || STATE->tx_index>=STATE->tx_count))) {
        STATE->tx_active=2u;return 16; /* Latched internal fault; never submit out-of-bounds bytes. */
    }
    if(STATE->lifecycle==2u)return 32; /* Watchdog-only software park, not a verified physical exit. */
    status=STATUS;kind=(unsigned char)(status>>5);
    if(STATE->lifecycle==1u && !STATE->tx_active && !STATE->rx_count && !STATE->discard && status==0u) {
        STATE->lifecycle=2u;return 32;
    }
    if(kind>=1u && kind<=4u) {
        value=DATA;
        if(STATE->tx_active || STATE->discard || STATE->lifecycle)return 0;
        if(STATE->rx_count>=AL5_RO_RX_BYTES){STATE->discard=1;return 8;}
        RX[STATE->rx_count++]=value;return 0;
    }
    if(kind>=5u) {
        value=DATA;
        n=STATE->rx_count;
        STATE->rx_count=0;
        if(STATE->lifecycle || STATE->discard || STATE->tx_active || kind!=7u || (value&0xC0u)!=0u || n!=AL5_RO_RX_BYTES) {
            STATE->discard=0;return 4;
        }
        if(RX[0]!=0x6Du || RX[1]!=0x18u || RX[2]!=0xF0u || RX[3]!=AL5_RO_REQUEST_SERVICE)return 4;
        for(i=0;i<AL5_RO_REQUEST_BYTES;i++)REQUEST[i]=RX[4u+i];
        n=al5_ro_read(REQUEST,AL5_RO_REQUEST_BYTES,REPLY,AL5_RO_MAX_REPLY);
        if(n==0u)return 4;
        TX[0]=0x6D;TX[1]=0xF0;TX[2]=0x18;TX[3]=AL5_RO_REPLY_SERVICE;
        for(i=0;i<n;i++)TX[4u+i]=REPLY[i];
        STATE->tx_count=(unsigned short)(4u+n);STATE->tx_index=0;STATE->tx_active=1;return 1;
    }
    if(STATE->tx_active && (status&0x0Bu)==0u) {
        i=STATE->tx_index;
        COMMAND=(i==0u)?0x14u:((i+1u==STATE->tx_count)?0x0Cu:0x04u);
        DATA=TX[i];STATE->tx_index=(unsigned short)(i+1u);
        if(i+1u==STATE->tx_count)STATE->tx_active=0;
        return 2; /* Software FIFO submission only, never physical completion. */
    }
    return 0;
}

/* SPDX-License-Identifier: GPL-3.0-only */
#include "read_core.h"
/* No peripheral access, command dispatch, upload, erase, program or reset operation. */
static unsigned short crc16(const unsigned char *p, unsigned int n)
{
    unsigned short crc=0xFFFFu;
    unsigned int i,j;
    for(i=0;i<n;i++) {
        crc^=(unsigned short)((unsigned short)p[i]<<8);
        for(j=0;j<8;j++) crc=(unsigned short)((crc&0x8000u)?(crc<<1)^0x1021u:crc<<1);
    }
    return crc;
}
unsigned int al5_ro_read(const unsigned char *r, unsigned int length, unsigned char *out, unsigned int capacity)
{
    unsigned long address;
    unsigned short crc;
    unsigned int i,count,nonce=0;
    if((unsigned long)r!=AL5_RO_REQUEST_RAM || (unsigned long)out!=AL5_RO_REPLY_RAM) return 0;
    if(length!=AL5_RO_REQUEST_BYTES || r[0]!='A' || r[1]!='R' || r[2]!=1u || r[3]!=1u) return 0;
    crc=crc16(r,20u);
    if(r[20]!=(unsigned char)(crc>>8) || r[21]!=(unsigned char)crc) return 0;
    for(i=4;i<12;i++)nonce|=r[i];
    if(!nonce)return 0;
    count=r[19];
    if(count==0 || count>AL5_RO_MAX_DATA || capacity<22u+count)return 0;
    address=((unsigned long)r[16]<<16)|((unsigned long)r[17]<<8)|r[18];
    if(address>0xFFFFFul || count>0x100000ul-address)return 0;
    out[0]='a';out[1]='r';out[2]=1u;out[3]=0u;
    for(i=4;i<20;i++)out[i]=r[i];
    for(i=0;i<count;i++)out[20u+i]=*((volatile const unsigned char *)(address+i));
    crc=crc16(out,20u+count);
    out[20u+count]=(unsigned char)(crc>>8);out[21u+count]=(unsigned char)crc;
    return 22u+count;
}

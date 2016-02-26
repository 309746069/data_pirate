#pragma once

#include <sys/time.h>
#include "common.h"


#define PACKET_BUFSIZE                  (1800)

#define PKT_ACCEPT                      (0)
#define PKT_STOLEN                      (1)


struct _ethhdr
{
    unsigned char   h_dest[6];
    unsigned char   h_source[6];

#define _ETH_P_IP                       (0x0800)
#define _ETH_P_ARP                      (0x0806)
    unsigned short  h_proto;
};


struct _arphdr
{
    unsigned short  ar_hrd;         /* format of hardware address   */
    unsigned short  ar_pro;         /* format of protocol address   */
    unsigned char   ar_hln;         /* length of hardware address   */
    unsigned char   ar_pln;         /* length of protocol address   */

#define _ARP_REPLY                      (0x0002)
#define _ARP_REQUEST                    (0x0001)
    unsigned short  ar_op;          /* ARP opcode (command)         */

    // use char[] against package
    unsigned char   ar_sha[6];              /* sender hardware address      */
    unsigned char   ar_sip[4];              /* sender IP address            */
    unsigned char   ar_tha[6];              /* target hardware address      */
    unsigned char   ar_tip[4];              /* target IP address            */
};


struct _iphdr
{
#if defined(__LITTLE_ENDIAN_BITFIELD)
    unsigned char   ihl:4,
                    version:4;

#elif defined(__BIG_ENDIAN_BITFIELD)
    unsigned char   version:4,
                    ihl:4;

#else
    #error "check __LITTLE_ENDIAN_BITFIELD / __BIG_ENDIAN_BITFIELD"
#endif

    unsigned char   tos;
    unsigned short  tot_len;
    unsigned short  id;
    unsigned short  frag_off;
    unsigned char   ttl;
#define _IPPROTO_TCP                    (0x06)
    unsigned char   protocol;
    unsigned short  check;
    unsigned int    saddr;
    unsigned int    daddr;
    /*The options start here. */
};


struct _tcphdr
{
    unsigned short  source;
    unsigned short  dest;
    unsigned int    seq;
    unsigned int    ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    unsigned short  res1:4,
                    doff:4,
                    fin:1,
                    syn:1,
                    rst:1,
                    psh:1,
                    ack:1,
                    urg:1,
                    ece:1,
                    cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    unsigned short  doff:4,
                    res1:4,
                    cwr:1,
                    ece:1,
                    urg:1,
                    ack:1,
                    psh:1,
                    rst:1,
                    syn:1,
                    fin:1;
#else
    #error  "check __LITTLE_ENDIAN_BITFIELD / __BIG_ENDIAN_BITFIELD"
#endif  
    unsigned short  window;
    unsigned short  check;
    unsigned short  urg_ptr;
};


void
router(unsigned char *packet, unsigned int pkt_len, struct timeval *cap_time);

void
route_packet(void *pi);
#pragma once


// build option ================================================================
#define ___MESSAGE_LOG__
#define ___DEBUG__
#define ___LOG_CLEAN__
#define __LITTLE_ENDIAN_BITFIELD

#ifndef ___MODULE_NAME
    #define ___MODULE_NAME              "data_pirate"
#endif

#if !defined(__LITTLE_ENDIAN_BITFIELD) && !defined(__BIG_ENDIAN_BITFIELD)
    #define __LITTLE_ENDIAN_BITFIELD
    #warning "use default definition __LITTLE_ENDIAN_BITFIELD"
#endif


// common define ===============================================================
#ifndef TRUE
    #define TRUE                        (1)
#endif
#ifndef FALSE
    #define FALSE                       (0)
#endif
#ifndef true
    #define true                        (1)
#endif
#ifndef false
    #define false                       (0)
#endif

#define PACKET_BUFSIZE                  (1800)

#define PKT_ACCEPT                      (0)
#define PKT_STOLEN                      (1)

// struct define ===============================================================


#define _PORT_80                        (0x0050)


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
    unsigned char   check;
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


// function pointer ============================================================
int __log_out_null(char*, ...);
int __send_package_null(const unsigned char*, const unsigned int);

typedef int (*LOG_OUT_FUN)(char*, ...);
typedef int (*SEND_PACKAGE_FUN)(const unsigned char*, const unsigned int);

extern LOG_OUT_FUN          _log_out;
extern SEND_PACKAGE_FUN     _send_package;

// void duff_memclr(char*, unsigned int);
// void duff_memcpy(char*, char*, unsigned int);
unsigned int
_ntoh32(unsigned int);

unsigned short
_ntoh16(unsigned short);

unsigned int
_iptonetint32(char*);

unsigned char*
_netint32toip(unsigned int);

int
net_state_init( const unsigned char*,
                const unsigned char*,
                const unsigned int,
                const unsigned int,
                const unsigned int);



// function define =============================================================
#define _SET_LOG_OUT_FUN(__fun_)        _log_out      = (LOG_OUT_FUN)__fun_
#define _SET_SEND_PACKAGE_FUN(__fun_)   _send_package = (SEND_PACKAGE_FUN)__fun_

#define _SEND_PACKAGE(__pkt_, __pkt_size_)                                     \
    (*_send_package)((unsigned char*)__pkt_, (unsigned int)__pkt_size_)

// message log define
#if defined(___MESSAGE_LOG__) && defined(___LOG_CLEAN__)
    #define _MESSAGE_OUT(format, args...)                                      \
                    (*_log_out)(format,##args)
#elif defined(___MESSAGE_LOG__) && !defined(___LOG_CLEAN__)
    #define _MESSAGE_OUT(format, args...)                                      \
                    (*_log_out)(___MODULE_NAME":\t"format,##args)
#else
    #define _MESSAGE_OUT(format, args...)
#endif
// debug log define
#ifdef ___DEBUG__
    #define _DEBUG_LOG(format, args...)                                        \
                    _MESSAGE_OUT(format, ##args)
#else
    #define _DEBUG_LOG(format, args...)
#endif











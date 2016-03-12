#include "tcp_sender.h"

#include <string.h>
#include <stdlib.h>

#include "packet_info.h"
#include "common.h"
#include "router.h"
#include "net_state.h"
#include "rectifier.h"
#include "queue.h"


#define __EOL                   0
#define __NOP                   1
#define __MSS                   2
#define __WSOPT                 3
#define __SACK_PERMITTED        4
#define __SACK_BLOCK            5
#define __TSPOT                 8
#define __TCP_MD5               19
#define __UTO                   28
#define __TCP_AO                29


struct tcp_state
{
#define TCP_BUF_SIZE            1024*1024
    unsigned char       send_buf[TCP_BUF_SIZE];
    unsigned int        s_ptr;
    unsigned char       receive_buf[TCP_BUF_SIZE];
    unsigned int        r_ptr;

    unsigned int        here_buf_start_seq;     // send start record
    unsigned int        here_next_seq;          // send record
    unsigned int        there_buf_start_seq;    // receive start record
    unsigned int        there_next_seq;         // receive record
};


struct tcp_recorder
{
    unsigned int        ser_ip_ni32;
    unsigned short      ser_port_ni16;
    unsigned short      ser_mss;

    unsigned int        cli_ip_ni32;
    unsigned short      cli_port_ni16;
    unsigned short      cli_mss;

    struct tcp_state    fake_cli,       // connect to server
                        fake_ser;       // listen from client
};



struct tcp_recorder*
tr_malloc(void)
{
    struct tcp_recorder *tr     = 0;
    unsigned int        size    = sizeof(struct tcp_recorder);

    tr  = malloc(size);
    if(!tr) return 0;

    memset(tr, 0, size);
    return tr;
}


void
tr_free(struct tcp_recorder *tr)
{
    if(tr)
    {
        free(tr);
    }
}


void*
tr_create(void)
{
    struct tcp_recorder *tr = tr_malloc();
    return tr;
}


void
tr_destory(void *tr)
{
    tr_free(tr);
}


unsigned int
set_eth_hdr(struct _ethhdr  *eth,
            unsigned char   *smac,
            unsigned char   *dmac,
            unsigned short  proto)
{
    if(!eth || !smac || !dmac || !proto) return 0;

    memset(eth, 0, sizeof(struct _ethhdr));

    memcpy(eth->h_source, smac, 6);
    memcpy(eth->h_dest, dmac, 6);
    eth->h_proto    = _ntoh16(proto);

    return sizeof(struct _ethhdr);
}


// no check no option
unsigned int
set_ip_hdr( struct _iphdr   *ip,
            unsigned short  tot_len,
            unsigned short  id,
            unsigned char   ttl,
            unsigned char   protocol,
            unsigned int    src_netint32,
            unsigned int    dst_netint32)
{
    if(    !ip 
        || !tot_len
        || !protocol
        || !src_netint32
        || !dst_netint32)
        return 0;

    memset(ip, 0, sizeof(struct _iphdr));

    ip->version     = 4;
    ip->ihl         = sizeof(struct _iphdr)/4;
    ip->tos         = 0;
    ip->tot_len     = _ntoh16(tot_len);
    ip->id          = id ? _ntoh16(id) : _ntoh16(rand()%0xffff);
    ip->frag_off    = _ntoh16(0b010 << (8+5)); // do not fragment
    ip->ttl         = ttl ? ttl : (54-rand()%5);
    ip->protocol    = protocol;
    ip->check       = 0;
    ip->saddr       = src_netint32;
    ip->daddr       = dst_netint32;

    return ip->ihl*4;
}


#define __syn___                    0b00000001
#define __fin___                    0b00000010
#define __ack___                    0b00000100
#define __psh___                    0b00001000
#define __rst___                    0b00010000
#define __urg___                    0b00100000
#define __ece___                    0b01000000
#define __cwr___                    0b10000000
// no check
unsigned int
set_tcp_hdr(struct _tcphdr  *tcp,
            unsigned short  source,
            unsigned short  dest,
            unsigned int    seq,
            unsigned int    ack_seq,
            unsigned short  hdr_len,
            unsigned char   flags,
            unsigned short  window,
            unsigned short  urg_ptr,
            unsigned char   *opt,
            unsigned char   opt_len)
{
    if(    !tcp
        || !source
        || !dest
        || !hdr_len
        || !window)
        return 0;
    if(hdr_len > 15*4) return 0;

    memset(tcp, 0, hdr_len);
    if(opt)
    {
        if(!opt_len) return 0;
        else if(opt_len > hdr_len-sizeof(struct _tcphdr)) return 0;
        memcpy((unsigned char*)tcp + sizeof(struct _tcphdr), opt, opt_len);
    }

    tcp->source     = _ntoh16(source);
    tcp->dest       = _ntoh16(dest);
    tcp->seq        = _ntoh32(seq);
    tcp->res1       = 0;
    tcp->doff       = hdr_len/4;

#define SET_FLAG(name)  {tcp->name = ( flags != (flags&(~__##name##___)) );}
    SET_FLAG(syn);
    SET_FLAG(fin);
    SET_FLAG(ack);
    SET_FLAG(psh);
    SET_FLAG(rst);
    SET_FLAG(urg);
    SET_FLAG(ece);
    SET_FLAG(cwr);
#undef SET_FLAG(name)

    tcp->ack_seq    = tcp->ack ? _ntoh32(ack_seq) : 0;

    tcp->window     = _ntoh16(window);
    tcp->check      = 0;
    tcp->urg_ptr    = tcp->urg ? _ntoh16(urg_ptr) : 0;

    return tcp->doff*4;
}


unsigned int
set_tcp_payload(unsigned char   *tdp,
                unsigned char   *payload,
                unsigned int    pl_len)
{
    if(!tdp || !payload || !pl_len) return 0;
    memcpy(tdp, payload, pl_len);
    return pl_len;
}


unsigned int
do_send_tcp_pkt(// ethhdr
                unsigned char   *dst_mac,
                unsigned char   *src_mac,
                // iphdr
                unsigned short  ipid,
                unsigned char   ttl,
                unsigned int    dst_ip_ni32,
                unsigned int    src_ip_ni32,
                // tcphdr
                unsigned short  dst_port_ni16,
                unsigned short  src_port_ni16,
                unsigned int    seq,
                unsigned int    ack_seq,
                unsigned char   flags,
                unsigned short  window,
                unsigned short  urg_ptr,
                unsigned char   *tcp_opt,
                unsigned char   opt_len,
                // tcp data ptr
                unsigned char   *tcp_payload,
                unsigned int    pl_len
                )
{
// args check ------------------------------------------------------------------
    // ethhdr check
    if(!dst_mac || !src_mac) return 0;
    // iphdr check
    if(!dst_ip_ni32 || !src_ip_ni32) return 0;
    ipid    = (ipid ? ipid : rand()%0xffff);
    // tcphdr check
    if(!dst_port_ni16 || !src_port_ni16 || !flags) return 0;
    if(!tcp_opt && opt_len) return 0;
    // tcp payload check
    if(!tcp_payload && pl_len) return 0;

// local args declaration ------------------------------------------------------
    void            *pi     = pi_create_empty();
    unsigned char   *pkt    = get_pkt_ptr(pi);
    unsigned int    eth_len = sizeof(struct _ethhdr);
    unsigned int    ip_len  = sizeof(struct _iphdr);
    unsigned int    tcp_len = sizeof(struct _tcphdr) + opt_len;
    unsigned int    pkt_len = 0;
    unsigned int    ret_len = 0;

    if(!pi || !pkt) goto failed_return;

// set tcp payload -------------------------------------------------------------
    if(pl_len)
    {
        ret_len = set_tcp_payload(  pkt+eth_len+ip_len+tcp_len,
                                    tcp_payload, pl_len);
        if(!ret_len)
            goto failed_return;
        else
            pkt_len += ret_len;
    }

// set tcp hdr -----------------------------------------------------------------
    ret_len = set_tcp_hdr(  pkt+eth_len+ip_len,
                            _ntoh16(src_port_ni16),
                            _ntoh16(dst_port_ni16),
                            seq,
                            ack_seq,
                            tcp_len,
                            flags,
                            window,
                            urg_ptr,
                            tcp_opt,
                            opt_len);
    if(!ret_len)
        goto failed_return;
    else
        pkt_len += ret_len;

// set ip hdr ------------------------------------------------------------------
    ret_len = set_ip_hdr(   pkt+eth_len,
                            pkt_len+ip_len,
                            ipid,
                            ttl,
                            _IPPROTO_TCP,
                            src_ip_ni32,
                            dst_ip_ni32);
    if(!ret_len)
        goto failed_return;
    else
        pkt_len += ret_len;

// set eth hdr -----------------------------------------------------------------
    ret_len = set_eth_hdr(  pkt,
                            src_mac,
                            dst_mac,
                            _ETH_P_IP);
    if(!ret_len)
        goto failed_return;
    else
        pkt_len += ret_len;

// checksum & send -------------------------------------------------------------
    pi_set_pkt_len(pi, pkt_len);
    tcp_checksum(pi);
    ip_checksum(pi);

    _SEND_PACKAGE(get_pkt_ptr(pi), get_pkt_len(pi));

// return ----------------------------------------------------------------------
success_return:
    pi_destory(pi);
    return pkt_len;
failed_return:
    pi_destory(pi);
    return 0;
}


unsigned int
send_tcp_pkt(   unsigned int        dst_ip_ni32,
                unsigned int        src_ip_ni32,
                unsigned short      dst_port_ni16,
                unsigned short      src_port_ni16,
                unsigned int        seq,
                unsigned int        ack_seq,
                unsigned char       flags,
                unsigned short      window,
                unsigned char       *tcp_payload,
                unsigned int        pl_len,
                unsigned char       *tcp_opt,
                unsigned char       opt_len)
{
    unsigned char   *dst_mac    = is_target_in_LAN(dst_ip_ni32)
                                    ? device_mac_address(dst_ip_ni32)
                                    : device_mac_address(route_ip_netint32());
    return do_send_tcp_pkt( dst_mac,
                            my_mac_address(),
                            0,
                            0,
                            dst_ip_ni32,
                            src_ip_ni32,
                            dst_port_ni16,
                            src_port_ni16,
                            seq,
                            ack_seq,
                            flags,
                            window,
                            0,
                            tcp_opt,
                            opt_len,
                            tcp_payload,
                            pl_len);
}


unsigned int
tr_send_tcp_pkt(struct tcp_recorder *tr,
                unsigned char       send_to_client,
                unsigned int        send_len,
                unsigned int        ack_len,
                unsigned char       flags,
                unsigned char       *tcp_payload,
                unsigned int        pl_len)
{
    unsigned int    dst_ip_ni32     = 0;
    unsigned int    src_ip_ni32     = 0;
    unsigned short  dst_port_ni16   = 0;
    unsigned short  src_port_ni16   = 0;
    unsigned int    seq             = 0;
    unsigned int    ack_seq         = 0;
    unsigned int    ret             = 0;

    if(send_to_client)
    {
        dst_ip_ni32     = tr->cli_ip_ni32;
        src_ip_ni32     = tr->ser_ip_ni32;
        dst_port_ni16   = tr->cli_port_ni16;
        src_port_ni16   = tr->ser_port_ni16;
        seq             = tr->fake_ser.here_next_seq;
        ack_seq         = tr->fake_ser.there_next_seq + ack_len;
    }
    else
    {
        dst_ip_ni32     = tr->ser_ip_ni32;
        src_ip_ni32     = tr->cli_ip_ni32;
        dst_port_ni16   = tr->ser_port_ni16;
        src_port_ni16   = tr->cli_port_ni16;
        seq             = tr->fake_cli.here_next_seq;
        ack_seq         = tr->fake_cli.there_next_seq + ack_len;
    }

    ret = send_tcp_pkt( dst_ip_ni32,
                        src_ip_ni32,
                        dst_port_ni16,
                        src_port_ni16,
                        seq,
                        ack_seq,
                        flags,
                        65535,
                        tcp_payload,
                        pl_len,
                        0,
                        0);
    if(!ret) return 0;

    if(send_to_client)
    {
        tr->fake_ser.here_next_seq  += send_len;
        tr->fake_ser.there_next_seq += ack_len;
    }
    else
    {
        tr->fake_cli.here_next_seq  += send_len;
        tr->fake_cli.there_next_seq += ack_len;
    }

    return ret;
}


unsigned int
tr_send_multi_tcp_pkt(  struct tcp_recorder *tr,
                        unsigned char       send_to_client,
                        unsigned char       *payload,
                        unsigned int        pl_len)
{
    if(!tr || !payload || !pl_len) return 0;

    unsigned int    mss     = send_to_client ? tr->cli_mss : tr->ser_mss;
    unsigned int    count   = (pl_len + mss - 1) / mss;
    unsigned int    index   = 0;

    while(index < count)
    {
        unsigned int    len     = mss;
        unsigned char   flags   = __ack___;
        if(index == count-1)
        {
            len     = pl_len - index * mss;
            flags   |= __psh___;
        }

        tr_send_tcp_pkt(tr, send_to_client, len, 0,
                        flags, payload+index*mss, len);
        index ++;
    }

    return index;
}


unsigned int
tr_send_ack_to_client(  struct tcp_recorder *tr,
                        unsigned int        ack_len)
{
    return tr_send_tcp_pkt(tr, true, 0, ack_len, __ack___, 0, 0);
}


unsigned int
tr_send_fin_to_client(  struct tcp_recorder *tr,
                        unsigned int        ack_len)
{
    return tr_send_tcp_pkt(tr, true, 1, ack_len, __ack___|__fin___, 0, 0);
}


unsigned int
tr_send_multi_tcp_pkt_to_client(struct tcp_recorder *tr,
                                unsigned char       *payload,
                                unsigned int        pl_len)
{
    return tr_send_multi_tcp_pkt(tr, true, payload, pl_len);
}


void*
tr_init_c2s(void *pi)
{
    struct _tcphdr  *tcp    = get_tcp_hdr(pi);
    struct _iphdr   *ip     = get_ip_hdr(pi);

    if(!tcp || !ip) return 0;

    struct tcp_recorder *tr = tr_malloc();
    if(!tr) return 0;

    tr->ser_ip_ni32     = ip->daddr;
    tr->ser_port_ni16   = tcp->dest;
    tr->cli_ip_ni32     = ip->saddr;
    tr->cli_port_ni16   = tcp->source;
    tr->ser_mss         = 536;
    tr->cli_mss         = 536;

    tr->fake_cli.here_buf_start_seq     = _ntoh32(tcp->seq);
    tr->fake_cli.here_next_seq          = tr->fake_cli.here_buf_start_seq;
    tr->fake_cli.there_buf_start_seq    = _ntoh32(tcp->ack_seq);
    tr->fake_cli.there_next_seq         = tr->fake_cli.there_buf_start_seq;

    tr->fake_ser.here_buf_start_seq     = _ntoh32(tcp->ack_seq);
    tr->fake_ser.here_next_seq          = tr->fake_ser.here_buf_start_seq;
    tr->fake_ser.there_buf_start_seq    = _ntoh32(tcp->seq);
    tr->fake_ser.there_next_seq         = tr->fake_ser.there_buf_start_seq;

    return tr;
}


unsigned int
do_tr_fake_server_receive(struct tcp_recorder *tr, void *pi)
{
    // if(get_tcp_hdr(pi)->fin)
    //     tr_send_ack_to_client(tr, 1);
    // else
    //     tr_send_fin_to_client(tr, get_tcp_data_len(pi));
    tr_send_ack_to_client(tr, get_tcp_data_len(pi));
    unsigned char   p[1800]  = "HTTP/1.1 200 OK\r\nContent-Length: 1500\r\nContent-Type: text/html;charset=UTF-8\r\n\r\n<!DOCTYPE html>\r\n<html>\r\n<head>\r\n    <title>server_fuck_test</title>\r\n    </head>\r\n<body>\r\n<img src=\"http://i1.sinaimg.cn/IT/cr/2012/0618/941424605.png\">\r\n</body>\r\n</html>\r\n\r\n";
    tr_send_multi_tcp_pkt_to_client(tr, p, 1800);

    return true;
}


unsigned int
do_tr_fake_client_receive(struct tcp_recorder *tr, void *pi)
{
    return true;
}


unsigned int
do_tr_receive(struct tcp_recorder *tr, void *pi)
{
    if(!tr || !pi) return false;

    struct _iphdr   *ip = get_ip_hdr(pi);

    if(!ip) return false;

    return (ip->daddr == tr->ser_ip_ni32)
            ? do_tr_fake_server_receive(tr, pi)
            : do_tr_fake_client_receive(tr, pi);
}


unsigned int
tr_receive(void *tr, void *pi)
{
    return do_tr_receive(tr, pi);
}





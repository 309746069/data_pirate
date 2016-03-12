#include "tcp_sender.h"

#include <string.h>
#include <stdlib.h>

#include "packet_info.h"
#include "common.h"
#include "router.h"
#include "net_state.h"
#include "rectifier.h"


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
    unsigned int    ip_ni32;
    unsigned short  port_ni16;

    unsigned short  window;
    unsigned int    start_seq;
    unsigned int    seq;
    unsigned int    ack_seq;

    unsigned short  mss;
    unsigned char   sack_perm;  // true or false
    unsigned char   win_shift;
};



struct tcp_recorder
{
    struct tcp_state    here;   // us
    struct tcp_state    there;  // target (client or server)
#define HERE_WINDOW     0xffff
#define HERE_WIN_SHIFT  5
    unsigned short      ipid;
    unsigned char       tmp[HERE_WINDOW<<HERE_WIN_SHIFT]; // 256k
    unsigned char       here_is_server;
};


struct tr_pair
{
    struct tcp_recorder *tr_server; // here is server
    struct tcp_recorder *tr_client; // here is client
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
tr_create(unsigned char here_is_server)
{
    struct tcp_recorder *tr = tr_malloc();
    if(tr)
        tr->here_is_server  = here_is_server;
    return tr;
}


void*
tr_create_server(void)
{
    return tr_create(true);
}


void*
tr_create_client(void)
{
    return tr_create(false);
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
send_tcp_pkt(   struct tcp_recorder *tr,
                unsigned int        seq_add_offset,
                unsigned int        ack_add_offset,
                unsigned char       flags,
                unsigned char       *tcp_payload,
                unsigned int        pl_len,
                unsigned char       *tcp_opt,
                unsigned int        opt_len)
{
    if(!tr) return 0;
    if(!tcp_payload && pl_len) return 0;
    if(!tcp_opt && opt_len) return 0;

    void            *pi     = pi_create_empty();
    unsigned char   *pkt    = get_pkt_ptr(pi);
    unsigned int    eth_len = sizeof(struct _ethhdr);
    unsigned int    ip_len  = sizeof(struct _iphdr);
    unsigned int    tcp_len = sizeof(struct _tcphdr) + opt_len;
    unsigned int    pkt_len = 0;
    unsigned int    ret_len = 0;

    if(!pi || !pkt) goto failed_return;

    if(pl_len)
    {
        ret_len = set_tcp_payload(pkt+eth_len+ip_len+tcp_len,
                                    tcp_payload, pl_len);
        if(!ret_len) goto failed_return;
        else pkt_len += ret_len;
    }

    tr->here.ack_seq    += ack_add_offset;

    ret_len = set_tcp_hdr(  pkt+eth_len+ip_len,
                            _ntoh16(tr->here.port_ni16),
                            _ntoh16(tr->there.port_ni16),
                            tr->here.seq,
                            tr->here.ack_seq,
                            tcp_len,
                            flags,
                            tr->here.window,
                            0,
                            tcp_opt,
                            opt_len);
    if(!ret_len) goto failed_return;
    else pkt_len += ret_len;

    tr->here.seq        += seq_add_offset;

    tr->ipid += rand()%(0xffff);
    ret_len = set_ip_hdr(   pkt+eth_len,
                            pkt_len+ip_len,
                            tr->ipid,
                            0,
                            _IPPROTO_TCP,
                            tr->here.ip_ni32,
                            tr->there.ip_ni32);
    if(!ret_len) goto failed_return;
    else pkt_len += ret_len;

    unsigned char   *target_mac = is_target_in_LAN(tr->there.ip_ni32)
                                    ? device_mac_address(tr->there.ip_ni32)
                                    : device_mac_address(route_ip_netint32());
    ret_len = set_eth_hdr(  pkt,
                            my_mac_address(),
                            target_mac,
                            _ETH_P_IP);
    if(!ret_len) goto failed_return;
    else pkt_len += ret_len;

    pi_set_pkt_len(pi, pkt_len);
    tcp_checksum(pi);
    ip_checksum(pi);

    _SEND_PACKAGE(get_pkt_ptr(pi), get_pkt_len(pi));

success_return:
    pi_destory(pi);
    return pkt_len;
failed_return:
    pi_destory(pi);
    return 0;
}



unsigned int
save_there_opt(struct tcp_recorder *tr, void *pi)
{
    if(!tr || !pi) return false;
    unsigned char   *opt    = get_tcp_opt_ptr(pi);
    unsigned int    opt_len = get_tcp_opt_len(pi);
    unsigned int    index   = 0;

    if(!opt || !opt_len) return false;

    for(index=0; index<opt_len; )
    {

        if(__EOL == opt[index] || __NOP == opt[index])
        {
            index += 1;
            continue;
        }
        switch(opt[index])
        {
            case __MSS:
            {
                unsigned short  mss_ni16    = 0;
                memcpy(&mss_ni16, opt+index+2, 2);
                unsigned short  mss_max     = 1494 - sizeof(struct _ethhdr)
                                                - sizeof(struct _iphdr)
                                                - sizeof(struct _tcphdr)
                                                - 40;
                tr->there.mss   = _ntoh16(mss_ni16) > mss_max
                                    ? mss_max : _ntoh16(mss_ni16) ;
                break;
            }
            case __WSOPT:
                tr->there.win_shift = opt[index+2];
                break;
            case __SACK_PERMITTED:
                tr->there.sack_perm = true;
                break;
            case __SACK_BLOCK:
                break;
            case __TSPOT:
                break;
            case __TCP_MD5:
                break;
            case __UTO:
                break;
            case __TCP_AO:
                break;
            default:
                break;
        }
        index += opt[index+1];
    }

    return true;
}


unsigned int
save_there_tcp_state(struct tcp_recorder *tr, void *pi)
{
    if(!tr || !pi) return false;

    struct _iphdr   *ip     = get_ip_hdr(pi);
    struct _tcphdr  *tcp    = get_tcp_hdr(pi);

    if(!ip || !tcp) return false;

    if(false == save_there_opt(tr, pi)) return false;

    tr->there.ip_ni32   = ip->saddr;
    tr->there.port_ni16 = tcp->source;

    tr->there.window    = _ntoh16(tcp->window);
    tr->there.start_seq = _ntoh32(tcp->seq);
    tr->there.seq       = _ntoh32(tcp->seq);
    tr->there.ack_seq   = tcp->ack ? _ntoh32(tcp->ack_seq) : 0;

    return true;
}


unsigned int
init_here_tcp_state(struct tcp_recorder *tr,
                    unsigned int        ip_ni32,
                    unsigned short      port_ni16,
                    unsigned int        ack_seq)
{
    if(!tr || !ip_ni32 || !port_ni16) return false;

    tr->here.ip_ni32    = ip_ni32;
    tr->here.port_ni16  = port_ni16;

    tr->here.window     = HERE_WINDOW;
    tr->here.start_seq  = rand()%0xffffffff;
    tr->here.seq        = tr->here.start_seq;
    tr->here.ack_seq    = ack_seq;

    tr->here.mss        = 1494
                            - sizeof(struct _ethhdr)
                            - sizeof(struct _iphdr)
                            - sizeof(struct _tcphdr)
                            - 40;
    tr->here.sack_perm  = true;
    tr->here.win_shift  = HERE_WIN_SHIFT;

    return true;
}


// opt_buf == 40 return real len
unsigned int
make_my_tcp_syn_opt(struct tcp_recorder *tr,
                    unsigned char       *opt,
                    unsigned int        opt_buf_len)
{
    if(!tr || !opt) return 0;
    if(40 != opt_buf_len) return 0;

    memset(opt, __NOP, opt_buf_len);
    unsigned int    opt_len = 0;

    if(tr->here.mss)
    {
        opt[opt_len]    = __MSS;
        opt[opt_len+1]  = 4;
        opt[opt_len+2]  = _ntoh16(tr->here.mss) & 0xff;
        opt[opt_len+3]  = _ntoh16(tr->here.mss) >> 8 & 0xff;
        opt_len         += 4;
    }
    if(tr->here.sack_perm)
    {
        opt[opt_len]    = __SACK_PERMITTED;
        opt[opt_len+1]  = 2;
        opt_len         += 2;
    }
    if(tr->here.win_shift)
    {
        opt[opt_len]    = __WSOPT;
        opt[opt_len+1]  = 3;
        opt[opt_len+2]  = tr->here.win_shift;
        opt_len         += 3;
    }

    // tr->here.last_tsval = _ntoh16(1457082200);
    // opt[opt_len]    = __TSPOT;
    // opt[opt_len+1]  = 10;
    // memcpy(opt + opt_len + 2, &tr->here.last_tsval, 4);
    // memset(opt + opt_len + 2 + 4, 0, 4);
    // opt_len +=10;

    opt_len += 3;
    opt_len /= 4;

    return opt_len*4;
}



unsigned int
tcp_syn_handler(struct tcp_recorder *tr, void *pi)
{
    if(!tr || !pi) return false;

    struct _iphdr   *ip     = get_ip_hdr(pi);
    struct _tcphdr  *tcp    = get_tcp_hdr(pi);

    if(!ip || !tcp) return false;

    if( false == save_there_tcp_state(tr, pi) ) return false;

    if( false ==
        init_here_tcp_state(tr, ip->daddr, tcp->dest, _ntoh32(tcp->seq)) )
        return false;

    unsigned char   opt[40] = {0};
    unsigned int    len     = make_my_tcp_syn_opt(tr, opt, 40);

    send_tcp_pkt(tr, 1, 1, __syn___|__ack___, 0, 0, opt, len);

    return true;
}


unsigned int
send_multi_tcp_pkt( struct tcp_recorder *tr,
                    unsigned char       *payload,
                    unsigned int        pl_len)
{
    if(!tr || !payload || !pl_len) return 0;

    unsigned int    mss     = tr->there.mss;
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

        send_tcp_pkt(tr, len, 0, flags, payload+index*mss, len, 0, 0);
        index ++;
    }
    return index;
}


unsigned int
do_tr_server_receive(struct tcp_recorder *tr, void *pi)
{
    struct _tcphdr  *tcp    = get_tcp_hdr(pi);
    if(!tr || !tcp) return false;

    // client syn
    if(tcp->syn && !tcp->ack)
    {
        return tcp_syn_handler(tr, pi);
    }

    if(tcp->fin)
        send_tcp_pkt(tr, 1, 1, __ack___|__fin___, 0,0,0,0);
    if(get_tcp_data_len(pi))
        send_tcp_pkt(tr, 0, get_tcp_data_len(pi), __ack___, 0,0,0,0);


    if(get_http_hdr_len(pi))
    {
        unsigned char   *p  = "HTTP/1.1 200 OK\r\nContent-Length: 1500\r\nContent-Type: text/html;charset=UTF-8\r\n\r\n<!DOCTYPE html>\r\n<html>\r\n<head>\r\n    <title>server_fuck_test</title>\r\n    </head>\r\n<body>\r\n<img src=\"http://i1.sinaimg.cn/IT/cr/2012/0618/941424605.png\">\r\n</body>\r\n</html>\r\n\r\n";
        memcpy(tr->tmp, p, strlen(p));
        return send_multi_tcp_pkt(tr, tr->tmp, HERE_WINDOW);
    }

    return false;
}


unsigned int
do_tr_client_receive(struct tcp_recorder *tr, void *pi)
{
    static void *rt = 0;
    struct _tcphdr  *tcp    = get_tcp_hdr(pi);
    if(!tr || !tcp) return false;


    // server syn&ack
    if(tcp->syn && tcp->ack)
    {
        static int i=0;
        if(i) return false;
        if( false == save_there_tcp_state(tr, pi) ) return false;
        send_tcp_pkt(tr, 0, _ntoh32(tcp->seq)+1, __ack___, 0,0,0,0);
        unsigned char   p[1800] = "GET / HTTP/1.1\r\nHost: www.163.com\r\nPragma: no-cache\r\nCookie: adRandomCookie=1; City=010; Province=010; _ga=GA1.2.1630912293.1453532520; _ntes_nnid=0e3fe0bbaebb90b4b3ba74541b8ac652,1450511953398; _ntes_nuid=0e3fe0bbaebb90b4b3ba74541b8ac652; ne_analysis_trace_id=1457084903309; pver_n_f_l_n3=a; s_n_f_l_n3=4138ad022ecc8d721457084903531; usertrack=ZUcIhlaSYKwi9AM5ChILAg==; vinfo_n_f_l_n3=4138ad022ecc8d72.1.15.1450511953405.1457078852665.1457084954907; vjlast=1450511953.1457069170.11; vjuids=1b5790614.151b93fed10.0.94272351\r\nConnection: keep-alive\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/601.4.4 (KHTML, like Gecko) Version/9.0.3 Safari/601.4.4\r\nAccept-Language: zh-cn\r\nAccept-Encoding: none\r\nCache-Control: no-cache\r\n\r\n";
        send_multi_tcp_pkt(tr, p, strlen(p));
        i=1;
        return true;
    }

    if(tcp->fin)
    {
        send_tcp_pkt(tr, 0, 1, __ack___|__fin___, 0,0,0,0);
        // send_tcp_pkt(tr, 0, 1, __ack___|__fin___, 0,0,0,0);
        int ret = rect_read_data(rt, tr->tmp, HERE_WINDOW<<HERE_WIN_SHIFT, tr->there.start_seq+1);
        _MESSAGE_OUT("%*s\nlen : %d\n", ret, tr->tmp, ret);
        return true;
    }

    if(get_tcp_data_len(pi))
    {
        if(tr->here.ack_seq == _ntoh32(tcp->seq))
        {
            send_tcp_pkt(tr, 0, get_tcp_data_len(pi), __ack___, 0,0,0,0);
        }
        else
        {
            send_tcp_pkt(tr, 0, 0, __ack___, 0,0,0,0);
            return false;
        }

        if(!rt) rt = rect_create();
        rect_insert(rt, pi);

        return true;
    }

    return false;
}


unsigned int
do_tr_receive(struct tcp_recorder *tr, void *pi)
{
    if(!tr) return false;
    return tr->here_is_server 
                ? do_tr_server_receive(tr, pi)
                : do_tr_client_receive(tr, pi);
}


unsigned int
tr_receive(void *tr, void *pi)
{
    return do_tr_receive(tr, pi);
}


unsigned int
do_tr_client_init(  struct tcp_recorder *tr_client,
                    struct tcp_recorder *tr_server)
{
    if(!tr_client || !tr_server) return false;
    if(!tr_server->here_is_server) return false;
    if(tr_client->here_is_server) return false;

    if(false == init_here_tcp_state(tr_client,
                        tr_server->there.ip_ni32,
                        tr_server->there.port_ni16,
                        0) )
        return false;

    tr_client->there.ip_ni32    = tr_server->here.ip_ni32;
    tr_client->there.port_ni16  = tr_server->here.port_ni16;

    return true;
}


unsigned int
do_tr_cli_connect_to_ser(struct tcp_recorder *tr_client)
{
    if(!tr_client || tr_client->here_is_server) return false;
    if(!tr_client->there.ip_ni32 || !tr_client->there.port_ni16) return false;

    unsigned char   opt[40] = {0};
    unsigned int    len     = make_my_tcp_syn_opt(tr_client, opt, 40);

    return send_tcp_pkt(tr_client, 1, 0, __syn___, 0, 0, opt, len);
}


unsigned int
tr_client_init(void *tr_client, void *tr_server)
{
    return do_tr_client_init(tr_client, tr_server);
}


void*
tr_create_mitm(void *pi)
{
    unsigned int    size    = sizeof(struct tr_pair);
    struct tr_pair  *mitm   = malloc(size);

    if(!mitm) goto fail_return;

    memset(mitm, 0, size);

    mitm->tr_server = tr_create_server();
    mitm->tr_client = tr_create_client();
    if(!mitm->tr_server || !mitm->tr_client) goto fail_return;

    if(false == tr_receive(mitm->tr_server, pi))
        goto fail_return;

    if(false == tr_client_init(mitm->tr_client, mitm->tr_server))
        goto fail_return;

    if(false == do_tr_cli_connect_to_ser(mitm->tr_client))
        goto fail_return;

success_return:
    return mitm;

fail_return:
    if(mitm)
    {
        if(mitm->tr_client)
            tr_destory(mitm->tr_client);
        if(mitm->tr_server)
            tr_destory(mitm->tr_server);
        free(mitm);
    }
    return 0;
}


unsigned int
do_tr_receive_mitm(struct tr_pair *trp, void *pi)
{
    if(!trp || !trp->tr_client || !trp->tr_server) return false;
    if(!pi) return false;

    struct _iphdr   *ip = get_ip_hdr(pi);
    if(!ip) return false;

    if(ip->daddr == trp->tr_server->here.ip_ni32)
        return tr_receive(trp->tr_server, pi);
    else
        return tr_receive(trp->tr_client, pi);
}



unsigned int
tr_receive_mitm(void *trp, void *pi)
{
    return do_tr_receive_mitm(trp, pi);
}


void
do_tr_destory_mitm(struct tr_pair *trp)
{
    if(trp)
    {
        if(trp->tr_client)
            tr_destory(trp->tr_client);
        if(trp->tr_server)
            tr_destory(trp->tr_server);
        free(trp);
    }
}


void
tr_destory_mitm(void *trp)
{
    do_tr_destory_mitm(trp);
}


void
tr_test(void *pi)
{
    if(!get_tcp_hdr(pi)) return;
    static struct tcp_recorder *cli = 0;

#define TEST_TARGET         "124.202.166.57"
    static test_port    = 0;
    if(!test_port)
    {
        srand(time(0));
        test_port = rand()%6000+20000;
    }
    if(!cli)
    {
        // if(get_ip_hdr(pi)->daddr != _iptonetint32("99.99.99.99")) return;
        cli = tr_create_client();

        if(false == init_here_tcp_state(cli,
                    _iptonetint32("192.168.1.114"),
                    _ntoh16(test_port),
                    0) )
            return;

        cli->there.ip_ni32    = _iptonetint32(TEST_TARGET);
        cli->there.port_ni16  = _ntoh16(80);
        do_tr_cli_connect_to_ser(cli);

        // _MESSAGE_OUT("send .......................\n");
    }

    if(get_ip_hdr(pi)->saddr != _iptonetint32(TEST_TARGET))
        return ;
    if(get_tcp_hdr(pi)->dest != _ntoh16(test_port))
        return;
    // _MESSAGE_OUT("in.....\n");

    do_tr_client_receive(cli, pi);
}










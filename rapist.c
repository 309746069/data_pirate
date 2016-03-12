#include "rapist.h"

#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "packet_info.h"
#include "stalker.h"
#include "router.h"
#include "tcp_stream.h"
#include "tcp_sender.h"


unsigned int rapist_one_shot_init(void *pi);

void    *tss    = 0;

int (*rapist_filter)(void*) = rapist_one_shot_init;



void
http_hdr_logout(void *pi)
{
    unsigned char   *http   = get_http_ptr(pi);
    unsigned int    hdr_len = get_http_hdr_len(pi);

    if(!http || !hdr_len)
        return;
        // _MESSAGE_OUT("[!]no http header\n");

    unsigned char   out[1800]   = {0};
    memcpy(out, http, hdr_len);
    _MESSAGE_OUT("===========================\n%s", out);
}


unsigned int
get_uri_from_pi(void *pi, unsigned char *retbuf, unsigned int bufsize)
{
    unsigned char   *http   = get_http_ptr(pi);

    unsigned char   buf[PACKET_BUFSIZE] = {0};

    if(0 == http || get_pkt_ptr(pi) + get_pkt_len(pi) < http) return false;

    if('G' == *http)
    {
        sscanf(http, "GET %s HTTP", buf);
        unsigned int    len = strlen(buf);

        if(bufsize >= len)
        {
            memcpy(retbuf, buf, len);
            return len;
        }
        // else
        // {
        //     memcpy(retbuf, buf, bufsize);
        //     return bufsize;
        // }
    }

    return false;
}


void
uri_logout(void *pi)
{
    unsigned char   uri[PACKET_BUFSIZE] = {0};
    unsigned int    uri_len = get_uri_from_pi(pi, uri, PACKET_BUFSIZE);
    if(uri_len
// #if 1
//        && strnstr(uri, ".js", uri_len)
// #else
//        && !strnstr(uri, ".jpg", uri_len)
//        && !strnstr(uri, ".swf", uri_len)
//        && !strnstr(uri, ".png", uri_len)
//        && !strnstr(uri, ".mp4", uri_len)
// #endif
        )
        _MESSAGE_OUT("%s\n", uri);
}


// in stalker thread ===========================================================

// return false to exit this stalker thread
unsigned int
stalker_callback(void *si, void *pi)
{
    // uri_logout(pi);
    // http_hdr_logout(pi);

    void    *tr = stalker_get_exptr(si);
    if(!tr)
    {
        struct _tcphdr  *tcp    = get_tcp_hdr(pi);
        tr  = tr_init_c2s(pi);
        if(!tr) return false;
        stalker_set_exptr(si, tr);
    }
    tr_receive(tr, pi);

    // route_packet(pi);
    // pi_destory(pi);
    return true;
}


// in router thread ============================================================
unsigned int
follow_this_beauty(void *pi)
{
    struct _tcphdr  *tcp    = get_tcp_hdr(pi);
    if(0 == tcp) return false;

    if( (_ntoh16(80) == tcp->dest)
            ? tss_c2s_insert(tss, pi)
            : tss_s2c_insert(tss, pi) )
    {
        void    *si = stalker_create();
        if(!si) return false;
        stalker_set_callback(si, stalker_callback);
        return tss_set_stalker(tss, pi, si);
    }

    return false;
}


unsigned int
fuck_my_baby(void *si, void *pi)
{
    return si ? stalker_push_new_ptr(si, pi) : false;
}


void*
is_my_girl(void *pi)
{
    return tss_get_stalker(tss, pi);
}


unsigned int
i_wanna_fuck_this_beauty(void *pi)
{
    unsigned char   *http   = get_http_ptr(pi);
    unsigned int    tdl     = get_tcp_data_len(pi);

    if(!http || !tdl) return false;
    if(http - get_pkt_ptr(pi) + 4 >= tdl) return false;


    if('G'==http[0] && 'E'==http[1] && 'T'==http[2] && ' '==http[3])
    {
#if 1
        static int i = 0;
        if(i) return false;
        struct _tcphdr  *tcp    = get_tcp_hdr(pi);
        struct _iphdr   *ip     = get_ip_hdr(pi);
        _MESSAGE_OUT("Hook one ip test !!! switch in file : %s:%d\n",
                            __FILE__, __LINE__ - 6);
        _MESSAGE_OUT("=============\nip.addr == %s && tcp.port == %u\n",
                            _netint32toip(ip->daddr), _ntoh16(tcp->source));
        i = 1;
#endif
        return true;
    }

    return false;
}


unsigned int
fuck_filter(void *pi)
{
    void    *stalker    = is_my_girl(pi);
    if(stalker)
    {
        return fuck_my_baby(stalker, pi);
    }

    else if(i_wanna_fuck_this_beauty(pi))
    {
        return follow_this_beauty(pi) && fuck_filter(pi);
    }

    return false;
}


unsigned int
rapist_one_shot_init(void *pi)
{
    rapist_filter = fuck_filter;

    // _MESSAGE_OUT("===========================one shot init!!!!!\n");
    while(!tss) tss = tss_create();

    return (*rapist_filter)(pi);
}


unsigned int
rapist(void *pi)
{
    return (*rapist_filter)(pi);
}

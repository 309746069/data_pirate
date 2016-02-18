#include "http.h"

#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "router.h"
#include "packet_info.h"
#include "gzip_wrapper.h"
#include "tcp_stream.h"


unsigned short
checksum(unsigned short *buf, unsigned int nword)
{
    unsigned long sum   = 0;
    for(sum=0; nword>0; nword--)
    {
        sum += *buf++;
        sum = (sum>>16) + (sum&0xffff);
    }
    return ~sum;
}


void
ip_checksum(void *pi)
{
    struct _iphdr   *ip     = get_ip_hdr(pi);
    if(0 == ip) return;

    ip->check   = 0;
    ip->check   = checksum(ip, ip->ihl*4/2);
}


void
tcp_checksum(void *pi)
{
    unsigned char   pkt[PACKET_BUFSIZE] = {0};
    struct _tcphdr  *tcp    = get_tcp_hdr(pi);
    struct _iphdr   *ip     = get_ip_hdr(pi);

    if(0 == tcp || 0 == ip) return;
    memset(pkt, 0, PACKET_BUFSIZE);

    unsigned int    size = _ntoh16(ip->tot_len) - ip->ihl*4;

    struct tcp_check
    {
        unsigned int    saddr;
        unsigned int    daddr;
        unsigned char   mbz;
        unsigned char   proto;
        unsigned short  tl;
        struct _tcphdr  tcp;
    }*tc = pkt;

    tc->saddr   = ip->saddr;
    tc->daddr   = ip->daddr;
    tc->mbz     = 0;
    tc->proto   = _IPPROTO_TCP;
    tc->tl      = _ntoh16((unsigned short)size);
    memcpy(&(tc->tcp), tcp, size);
    tc->tcp.check   = 0;

    tcp->check  = checksum(pkt, (size+12+1)/2);
}



int one_shot_init(void *pi);

void    *tss    = 0;

int (*http_handle_fun)(void*) = one_shot_init;


int
http_handler(void *pi)
{
    unsigned char   *http   = get_http_ptr(pi);
#if 1
    if(tss_search(tss, pi))
    {
        _MESSAGE_OUT("yes!!!\n");
    }
#endif

#if 1
    if(get_http_hdr_len(pi))
    {
        // if('G' == *http || 'P' == *http)
        if('H' == *http)
        {
            unsigned char   out[100000]   = {0};
            unsigned int    olen        = 100000;
            unsigned int    hdata_len   = 0;
            unsigned char   *p  = 0;
            memcpy(out, http, get_http_hdr_len(pi));

            if(strnstr(out, "chunked", 1800))
            {
                tss_insert(tss, pi) ? _MESSAGE_OUT("true") : _MESSAGE_OUT("false");
                _MESSAGE_OUT("============catch!!!!!\n");
            }
        }
    }
#endif

    return PKT_ACCEPT;
}


int
one_shot_init(void *pi)
{
    http_handle_fun = http_handler;

    // _MESSAGE_OUT("===========================one shot init!!!!!\n");
    while(!tss) tss = tss_create();

    return (*http_handle_fun)(pi);
}


int
http(void *pi)
{
    return (*http_handle_fun)(pi);
}


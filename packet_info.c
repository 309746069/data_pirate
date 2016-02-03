#include "packet_info.h"

#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "router.h"

struct packet_info
{
    unsigned char   packet[PACKET_BUFSIZE];
    unsigned int    pkt_len;
    struct timeval  cap_time;
};

void*
pi_create(unsigned char *packet, unsigned int pkt_len, struct timeval *cap_time)
{
    struct packet_info  *pi = malloc(sizeof(struct packet_info));
    if(0 == pi)
    {
        _MESSAGE_OUT("packet_info malloc failed!\n");
        return 0;
    }
    memset(pi, 0, sizeof(struct packet_info));

    memcpy(pi->packet, packet, pkt_len);
    memcpy(&(pi->cap_time), cap_time, sizeof(struct timeval));
    pi->pkt_len = pkt_len;

    return pi;
}


void
pi_destory(void *pi)
{
    if(pi)
    {
        free(pi);
    }
}


unsigned char*
get_pkt_ptr(void *pi)
{
    struct packet_info  *p  = pi;
    return p ? p->packet : 0;
}


unsigned int
get_pkt_len(void *pi)
{
    struct packet_info  *p  = pi;
    return p ? p->pkt_len : 0;
}


struct _ethhdr*
get_eth_hdr(void *pi)
{
    return get_pkt_ptr(pi);
}


struct _arphdr*
get_arp_hdr(void *pi)
{
    struct _ethhdr  *eth    = get_eth_hdr(pi);

    if(eth && _ntoh16(_ETH_P_ARP) == eth->h_proto)
    {
        return (unsigned char*)eth + sizeof(struct _ethhdr);
    }

    return 0;
}


struct _iphdr*
get_ip_hdr(void *pi)
{
    struct _ethhdr  *eth    = get_eth_hdr(pi);

    if(eth && _ntoh16(_ETH_P_IP) == eth->h_proto)
    {
        return (unsigned char*)eth + sizeof(struct _ethhdr);
    }

    return 0;
}


struct _tcphdr*
get_tcp_hdr(void *pi)
{
    struct _iphdr   *ip     = get_ip_hdr(pi);

    if(ip && _IPPROTO_TCP == ip->protocol)
    {
        return (unsigned char*)ip + ip->ihl * 4;
    }

    return 0;
}


unsigned char*
get_tcp_data_ptr(void *pi)
{
    struct _tcphdr  *tcp    = get_tcp_hdr(pi);
    unsigned char   *pd     = 0;
    if(0 == tcp) return 0;
    pd  = (unsigned char*)tcp + tcp->doff * 4;

    return pd - get_pkt_ptr(pi) > get_pkt_len(pi) ? 0 : pd;
}


unsigned int
get_tcp_data_len(void *pi)
{
    if(get_tcp_data_ptr(pi))
    {
        return get_pkt_len(pi) - (get_tcp_data_ptr(pi) - get_pkt_ptr(pi));
    }
    return 0;
}


unsigned char*
get_http_ptr(void *pi)
{
    struct _tcphdr  *tcp    = get_tcp_hdr(pi);
    if(tcp &&
            (_ntoh16(80) == tcp->source || _ntoh16(80) == tcp->dest))
    {
        if(get_tcp_data_len(pi))
            return (unsigned char*)tcp + tcp->doff * 4;
    }
    return 0;
}


unsigned int
get_http_hdr_len(void *pi)
{
    unsigned char   *http   = get_http_ptr(pi);
    unsigned char   *hdata  = 0;
    if(http)
    {
        hdata = strnstr(http, "\r\n\r\n", get_tcp_data_len(pi));
        return hdata ? (hdata - http + 4) : 0; // +4 for '\r\n\r\n'
    }
    return 0;
}







#include "router.h"

#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "net_state.h"
#include "http.h"
#include "packet_info.h"



int
is_our_packet(unsigned char *packet, unsigned int pkt_len)
{
    struct _ethhdr  *eth    = (struct _ethhdr*)packet;
    struct _iphdr   *ip     = 0;

    // packet error
    if(0 == packet || 0 == pkt_len)
    {
        return false;
    }

    // sent from us
    if(0 == memcmp(eth->h_source, my_mac_address(), 6))
    {
        return false;
    }

    // sent to us
    if(_ntoh16(_ETH_P_IP) == eth->h_proto)
    {
        ip  = packet + sizeof(struct _ethhdr);

        if( my_ip_netint32() == ip->daddr/* || my_ip_netint32() == ip->saddr*/)
        {
            return false;
        }
    }

    return true;
}


int
is_arp_packet(  const unsigned char*    packet,
                const unsigned int      pkt_len,
                const struct timeval    *cap_time)
{
    struct _ethhdr  *eth    = packet;

    if(_ntoh16(_ETH_P_ARP) != eth->h_proto)
    {
        return false;
    }

    struct _arphdr  *arp    = packet + sizeof(struct _ethhdr);
    unsigned int    ip      = 0;

    memcpy(&ip, arp->ar_sip, 4);
    set_host_info(ip, arp->ar_sha, cap_time->tv_sec);

    return true;
}


void
route_packet(void *pi)
{
    struct _ethhdr  *eth    = get_eth_hdr(pi);
    struct _iphdr   *ip     = get_ip_hdr(pi);

    if(0 == ip)
    {
        return;
    }

    if( is_target_in_LAN(ip->daddr) )
        memcpy(eth->h_dest, device_mac_address(ip->daddr), 6);
    else
        memcpy(eth->h_dest, device_mac_address(route_ip_netint32()), 6);

    _SEND_PACKAGE(get_pkt_ptr(pi), get_pkt_len(pi));
}



void
router(unsigned char *packet, unsigned int pkt_len, struct timeval *cap_time)
{
    if(false == is_our_packet(packet, pkt_len))
    {
        return;
    }

    if(true == is_arp_packet(packet, pkt_len, cap_time))
    {
        return;
    }

    void    *pi = pi_create(packet, pkt_len, cap_time);

    if(PKT_STOLEN == http(pi))
    {
        return;
    }

    route_packet(pi);
    pi_destory(pi);
}
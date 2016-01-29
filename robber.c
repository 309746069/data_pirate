#include "robber.h"

#include "common.h"
#include "net_state.h"
#include "tcp_handler.h"



void
robber_ip_handler(  const unsigned char*    packet,
                    const unsigned int      pkt_len,
                    const time_t            cap_time)
{
    struct _iphdr       *ip     = packet + sizeof(struct _ethhdr);
    struct _tcphdr      *tcp    = 0;
    int                 ret     = PKT_ACCEPT; 

    switch(ip->protocol)
    {
        case _IPPROTO_TCP:
            ret = tcp_handler(packet, pkt_len);
            break;
        default:
            ret = PKT_ACCEPT;
            break;
    }

    if(PKT_ACCEPT != ret)
    {
        return;
    }

    // send packet
    unsigned char       p[PACKET_BUFSIZE]   = {0};
    struct _ethhdr      *eth                = p;
    memcpy(p, packet, pkt_len);

    if( is_target_in_LAN(ip->daddr) )
        memcpy(eth->h_dest, device_mac_address(ip->daddr), 6);
    else
        memcpy(eth->h_dest, device_mac_address(route_ip_netint32()), 6);

    _SEND_PACKAGE(p, pkt_len);
}


void
robber_arp_handler( const unsigned char*    packet,
                    const unsigned int      pkt_len,
                    const time_t            cap_time)
{
    struct _arphdr  *arp    = packet + sizeof(struct _ethhdr);
    unsigned int    ip      = 0;

    memcpy(&ip, arp->ar_sip, 4);
    set_host_info(ip, arp->ar_sha, cap_time);
}


unsigned int
robber_opera_filter(const unsigned char* packet, const unsigned int pkt_len)
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


void
robber( const unsigned char*    packet,
        const unsigned int      pkt_len,
        const time_t            cap_time)
{
    struct _ethhdr  *eth    = (struct _ethhdr*)packet;

    if(false == robber_opera_filter(packet, pkt_len))
    {
        return;
    }

    switch( _ntoh16(eth->h_proto) )
    {
        case _ETH_P_ARP:
            robber_arp_handler(packet, pkt_len, cap_time);
            return;
        case _ETH_P_IP:
            robber_ip_handler(packet, pkt_len, cap_time);
            return;
        default:
            return;
    }
}
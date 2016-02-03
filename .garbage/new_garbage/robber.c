#include "robber.h"

#include "common.h"
#include "net_state.h"
#include "packet_wrapper.h"
#include "tcp_handler.h"



void
robber_ip_handler(void *pw)
{
    if(0 == pw)
    {
        return;

    }
    struct _iphdr       *ip     = pw_get_packet(pw) + sizeof(struct _ethhdr);
    struct _tcphdr      *tcp    = 0;
    int                 ret     = PKT_ACCEPT; 

    switch(ip->protocol)
    {
        case _IPPROTO_TCP:
            ret = tcp_handler(pw);
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
    struct _ethhdr      *eth    = pw_get_packet(pw);

    if( is_target_in_LAN(ip->daddr) )
        memcpy(eth->h_dest, device_mac_address(ip->daddr), 6);
    else
        memcpy(eth->h_dest, device_mac_address(route_ip_netint32()), 6);

    _SEND_PACKAGE(pw_get_packet(pw), pw_get_pkt_len(pw));
}


void
robber_arp_handler( const unsigned char*    packet,
                    const unsigned int      pkt_len,
                    const struct timeval    *cap_time)
{
    struct _arphdr  *arp    = packet + sizeof(struct _ethhdr);
    unsigned int    ip      = 0;

    memcpy(&ip, arp->ar_sip, 4);
    set_host_info(ip, arp->ar_sha, cap_time->tv_sec);
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
        const struct timeval    *cap_time)
{
    struct _ethhdr  *eth    = (struct _ethhdr*)packet;
    void            *pw     = 0;

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
            // todo: 内存泄漏问题
            pw  = pw_create(packet, pkt_len, cap_time);
            robber_ip_handler(pw);
            return;
        default:
            return;
    }
}
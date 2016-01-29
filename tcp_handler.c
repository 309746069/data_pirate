#include "tcp_handler.h"

#include "common.h"
#include "http_handler.h"



int
tcp_handler(const unsigned char *packet, const unsigned int pkt_len)
{
    int             ret     = PKT_ACCEPT;
    struct _ethhdr  *eth    = packet;
    struct _iphdr   *ip     = packet + sizeof(struct _ethhdr);
    struct _tcphdr  *tcp    = packet + sizeof(struct _ethhdr)
                                + sizeof(struct _iphdr);

#if 0
    _DEBUG_LOG("%15s:%u\t--->", _netint32toip(ip->saddr), _ntoh16(tcp->source));
    _DEBUG_LOG("%15s:%u\n", _netint32toip(ip->daddr), _ntoh16(tcp->dest));
#endif

    if(80 == _ntoh16(tcp->source) || 80 == _ntoh16(tcp->dest))
    {
        ret = http_handler(packet, pkt_len);
    }

    return ret;
}
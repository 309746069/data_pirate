#include "tcp_handler.h"

#include "common.h"
#include "packet_wrapper.h"
#include "http_handler.h"



int
tcp_handler(void *pw)
{
    int             ret     = PKT_ACCEPT;
    struct _ethhdr  *eth    = pw_get_packet(pw);
    struct _iphdr   *ip     = pw_get_packet(pw) + sizeof(struct _ethhdr);
    struct _tcphdr  *tcp    = pw_get_packet(pw) + sizeof(struct _ethhdr)
                                + sizeof(struct _iphdr);

#if 0
    _DEBUG_LOG("%15s:%u\t--->", _netint32toip(ip->saddr), _ntoh16(tcp->source));
    _DEBUG_LOG("%15s:%u\n", _netint32toip(ip->daddr), _ntoh16(tcp->dest));
#endif

    if(80 == _ntoh16(tcp->source) || 80 == _ntoh16(tcp->dest))
    {
        ret = http_handler(pw);
    }

    return ret;
}
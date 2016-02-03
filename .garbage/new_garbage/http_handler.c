#include "http_handler.h"

#include <string.h>

#include "common.h"
#include "packet_wrapper.h"

int
http_handler(void *pw)
{
    int             ret     = PKT_ACCEPT;
    struct _ethhdr  *eth    = pw_get_packet(pw);
    struct _iphdr   *ip     = pw_get_packet(pw) + sizeof(struct _ethhdr);
    struct _tcphdr  *tcp    = pw_get_packet(pw) + sizeof(struct _ethhdr)
                                + sizeof(struct _iphdr);
    unsigned char   *http   = (unsigned char*)tcp + tcp->doff*sizeof(int);
    unsigned int    h_len   = pw_get_pkt_len(pw) - (http - pw_get_packet(pw));


    static unsigned int     src_ip = 0, dst_ip = 0;
    static unsigned short   src_port = 0, dst_port = 0;

    if(('G' == *http || 'P' == *http/* || 'H' == *http */)
#if 0
        || src_ip == ip->saddr
#endif
        )
    {
        int len = 0;
        unsigned char* p = 0;
#if 0
        if(0 == src_ip){
            if(0 == strnstr(http, "Transfer-Encoding: chunked\r\n", h_len)
                || 0 == strnstr(http, "Content-Type: text/html", h_len))
            {
                return ret;
            }
            src_ip  = ip->saddr;
            dst_ip  = ip->daddr;
            src_port    = tcp->source;
            dst_port    = tcp->dest;
            _MESSAGE_OUT("ip.src == %s &&", _netint32toip(ip->saddr));
            _MESSAGE_OUT("ip.dst == %s && tcp.port == %u \n", _netint32toip(ip->daddr), _ntoh16(tcp->dest));
        }

        if(src_ip == ip->saddr && dst_ip == ip->daddr
            && src_port == tcp->source && dst_port == tcp->dest)
        {
            _MESSAGE_OUT("seq : %08X  ack_seq : %08X  data_len : %08u  next seq : %08X\n",
                     _ntoh32(tcp->seq), _ntoh32(tcp->ack_seq), h_len, _ntoh32(tcp->seq) + h_len);
            return ret;
        }
        return ret;
#endif

        unsigned char   fun[30]     = {0};
        unsigned char   uri[1000]   = {0};
        unsigned char   host[100]   = {0};

        p = strnstr(http, "\r\n\r\n", h_len);
        if(!p)
        {
            return ret;
        }

        sscanf(http, "%s %s HTTP", fun, uri);
        p = strnstr(http, "Host:", h_len);
        if(p)
        {
            sscanf(p, "Host: %s", host);
        }
        else
        {
            memcpy(host, _netint32toip(ip->daddr), strlen(_netint32toip(ip->daddr)));
        }

        _MESSAGE_OUT("%s %s%s\n", fun, host, uri);
        return ret;


        unsigned char out[PACKET_BUFSIZE]   = {0};
        memset(out, 0, PACKET_BUFSIZE);
        memcpy(out, http, p-http);
        _DEBUG_LOG("==========================================\n");
        _DEBUG_LOG("%s\n", out);
    }


    return ret;
}
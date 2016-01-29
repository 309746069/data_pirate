#include "http_handler.h"

#include <string.h>

#include "common.h"

int
http_handler(const unsigned char *packet, const unsigned int pkt_len)
{
    int             ret     = PKT_ACCEPT;
    struct _ethhdr  *eth    = packet;
    struct _iphdr   *ip     = packet + sizeof(struct _ethhdr);
    struct _tcphdr  *tcp    = packet + sizeof(struct _ethhdr)
                                + sizeof(struct _iphdr);
    unsigned char   *http   = (unsigned char*)tcp + tcp->doff*sizeof(int);
    unsigned int    h_len   = pkt_len - (http - packet);

    if('G' == *http || 'P' == *http || 'H' == *http)
    {
        int len = 0;
        unsigned char* p = 0;
        p = strnstr(http, "\r\n\r\n", h_len);
        if(!p)
        {
            return ret;
        }
        unsigned char out[PACKET_BUFSIZE]   = {0};
        memset(out, 0, PACKET_BUFSIZE);
        memcpy(out, http, p-http);
        _DEBUG_LOG("==========================================\n");
        _DEBUG_LOG("%s\n", out);
    }


    return ret;
}
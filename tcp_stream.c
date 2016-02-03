#include "tcp_stream.h"

#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "router.h"
#include "packet_info.h"



struct tcp_stream
{
    unsigned int    client_ip;
    unsigned short  client_port;
    unsigned int    server_ip;
    unsigned short  server_port;
};


int
ts_equal(struct tcp_stream *ts1, struct tcp_stream *ts2)
{
    return (    (ts1->client_port   == ts2->client_port)
            &&  (ts1->server_ip     == ts2->server_ip)
            &&  (ts1->client_ip     == ts2->client_ip)
            &&  (ts1->server_port   == ts2->server_port) );
}



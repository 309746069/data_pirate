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

struct ts_node
{
    struct tcp_stream   t;
    struct ts_node      *ln;    // list next node
    struct ts_node      *lp;    // list previous node
    struct ts_node      *hn;    // hash table list next node
    struct ts_node      *hp;    // hash table list previous node
};

struct ts_storage
{
    struct ts_node  *lr;    // list root
    struct ts_node  *le;    // list end
    unsigned int    ncount; // node counter

#ifndef MAX_TABLE
    #define MAX_TABLE       100
#endif
    struct ts_node  *ht[MAX_TABLE]; // hash table
};


int
ts_equal(struct tcp_stream *ts1, struct tcp_stream *ts2)
{
    return (    (ts1->client_port   == ts2->client_port)
            &&  (ts1->server_ip     == ts2->server_ip)
            &&  (ts1->client_ip     == ts2->client_ip)
            &&  (ts1->server_port   == ts2->server_port) )
        ||
           (    (ts1->client_port   == ts2->server_port)
            &&  (ts1->server_ip     == ts2->client_ip)
            &&  (ts1->client_ip     == ts2->server_ip)
            &&  (ts1->server_port   == ts2->client_port) );
}


unsigned int
hash_index(struct tcp_stream *ts)
{
    return (ts->client_ip + ts->client_port
                + ts->server_ip + ts->server_port)
                % MAX_TABLE;
}


struct ts_node*
ts_malloc(void)
{
    struct ts_node  *ts     = 0;
    unsigned int    size    = sizeof(struct ts_node);

    ts  = (struct ts_node*)malloc(size);
    if(0 == ts)
    {
        return 0;
    }

    memset(ts, 0, size);
    return ts;
}


void
ts_free(struct ts_node *ts)
{
    if(ts)
    {
        free(ts);
    }
}


void*
tss_create(void)
{
    struct ts_storage   *tss    = 0;
    unsigned int        size    = sizeof(struct ts_storage);

    tss = (struct ts_storage*)malloc(size);
    if(0 == tss)
    {
        return 0;
    }

    memset(tss, 0, size);
    return (void*)tss;
}




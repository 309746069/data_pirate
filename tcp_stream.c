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
    struct tcp_stream   tstream;
    struct ts_node      *ln;    // list next node
    struct ts_node      *lp;    // list previous node
    struct ts_node      *hn;    // hash table list next node
    struct ts_node      *hp;    // hash table list previous node
};

struct ts_storage
{
    struct ts_node  *lr;    // list root
    struct ts_node  *le;    // list end

#ifndef MAX_TABLE
    #define MAX_TABLE       100
#endif
    struct ts_node  *ht[MAX_TABLE]; // hash table
};


int
ts_equal(struct tcp_stream *ts1, struct tcp_stream *ts2)
{
    return 
           (    (ts1->client_port   == ts2->client_port)
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
    unsigned long   sum     = 0;
    unsigned long   port    = 0;
    unsigned long   ip      = 0;

    port    = ts->client_port + ts->server_port;
    port    = (port>>16) + (port&0xffff);

    ip      = ts->client_ip + ts->server_ip;
    ip      = (ip>>16) + (ip&0xffff);

    sum     = port + ip;
    sum     = (sum>>16) + (sum&0xffff);

    return sum % MAX_TABLE;
}


struct ts_node*
tn_malloc(void)
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
tn_free(struct ts_node *ts)
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

    return tss;
}


unsigned int
is_tss_empty(void *tss)
{
    struct ts_storage   *t  = tss;

    return 0==t->lr && 0==t->le;
}



struct ts_node**
find_my_hash_head(void *tss, struct tcp_stream *ts)
{
    struct ts_storage   *t  = tss;

    return t ? &(t->ht[hash_index(ts)]) : 0;
}


// if return 0, hash table list is empty, got root node pointer
// if return a pointer, maybe this ts is in the list or not,
//  check by ts_equal function
struct ts_node**
find_my_hash_seat(void *tss, struct tcp_stream *ts)
{
    struct ts_node  **t  = find_my_hash_head(tss, ts);

    while(t && *t && (*t)->hn && !ts_equal(&((*t)->tstream), ts)) *t = &((*t)->hn);

#if 0
    _MESSAGE_OUT("=========================\n");

    if(t && ts_equal(&(t->tstream), ts))
    {
        _MESSAGE_OUT("%15s : %5u ---> ", _netint32toip(ts->client_ip), _ntoh16(ts->client_port));
        _MESSAGE_OUT("%15s : %5u\n", _netint32toip(ts->server_ip), _ntoh16(ts->server_port));
    }
#endif

    return t;
}


unsigned int
tss_insert(void *tss, void *pi)
{
    struct ts_storage   *t      = tss;
    struct ts_node      **tn    = 0;
    struct tcp_stream   ts      = {0};
    struct ts_node      *node   = 0;

    if(0 == t || 0 == pi)  return false;

    if(0 == get_tcp_hdr(pi) || 0 == get_ip_hdr(pi)) return false;
    ts.client_ip    = get_ip_hdr(pi)->saddr;
    ts.server_ip    = get_ip_hdr(pi)->daddr;
    ts.client_port  = get_tcp_hdr(pi)->source;
    ts.server_port  = get_tcp_hdr(pi)->dest;

    tn  = find_my_hash_seat(tss, &ts);

    // already in the storage
    if(*tn && ts_equal(&((*tn)->tstream), &ts)) return false;

    node    = tn_malloc();
    if(0 == node) return false;
    memcpy(&(node->tstream), &ts, sizeof(struct tcp_stream));

    // hash table operation
    if(*tn)
    {
        node->hp    = *tn;
        node->hn    = 0;
        (*tn)->hn      = node;
    }
    else
    {
        *tn         = node;
        node->hp    = 0;
        node->hn    = 0;
    }

    // list operation
    if(is_tss_empty(tss))
    {
        t->lr       = node;
        t->le       = node;
        node->lp    = 0;
        node->ln    = 0;
    }
    else
    {
        t->le->ln   = node;
        node->lp    = t->le;
        node->ln    = 0;
        t->le       = node;
    }


    return true;
}


struct tcp_stream*
do_tss_search(void *tss, void *pi)
{
    struct ts_storage   *t      = tss;
    struct ts_node      **tn     = 0;
    struct tcp_stream   ts      = {0};

    if(0 == t || 0 == pi)  return 0;

    if(0 == get_tcp_hdr(pi) || 0 == get_ip_hdr(pi)) return 0;
    ts.client_ip    = get_ip_hdr(pi)->saddr;
    ts.server_ip    = get_ip_hdr(pi)->daddr;
    ts.client_port  = get_tcp_hdr(pi)->source;
    ts.server_port  = get_tcp_hdr(pi)->dest;

    tn  = find_my_hash_seat(tss, &ts);

    return (*tn && ts_equal(&((*tn)->tstream), &ts)) ? &(*tn)->tstream : 0;
}


unsigned int
tss_search(void *tss, void *pi)
{
#if 0
    struct ts_storage   *t      = tss;
    struct ts_node      *node   = 0;
    if(!t) return false;
    _MESSAGE_OUT("============================\n");
    for(node = t->lr; node ; node = node->ln)
    {
        struct tcp_stream   *ts = &(node->tstream);
        _MESSAGE_OUT("%-15s : %u ---> ", _netint32toip(ts->client_ip), _ntoh16(ts->client_port));
        _MESSAGE_OUT("%-15s : %u\n", _netint32toip(ts->server_ip), _ntoh16(ts->server_port));
    }
#endif
    return do_tss_search(tss, pi) ? true : false;
}















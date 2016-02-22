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

    unsigned int    s2c_insert_data_size;
    unsigned int    s2c_insert_start_seq;
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


unsigned int
ht_insert(struct ts_storage *tss, struct ts_node *tn)
{
    struct ts_node  *iter   = 0;
    if(0 == tss || 0 == tn) return false;

    unsigned int    hi  = hash_index(&tn->tstream);

    // hash list is empty
    if(0 == tss->ht[hi])
    {
        tss->ht[hi] = tn;
        tn->hn      = 0;
        tn->hp      = 0;
        return true;
    }

    iter    = tss->ht[hi];
    // hash list not empty
    while( !ts_equal(&(iter->tstream), &(tn->tstream))
            && iter->hn )
        iter    = iter->hn;

    // already in the list
    if(ts_equal(&(iter->tstream), &(tn->tstream)))
        return false;

    // not in the list
    tn->hp      = iter;
    tn->hn      = 0;
    iter->hn    = tn;

    return true;
}


unsigned int
li_add_to_end(struct ts_storage *tss, struct ts_node *tn)
{
    if(0 == tss || 0 == tn) return false;

    // list empty
    if(0 == tss->lr || 0 == tss->le)
    {
        tn->lp  = 0;
        tn->ln  = 0;
        tss->lr = tn;
        tss->le = tn;
        return true;
    }

    // list not empty & change the end of list
    tn->lp      = tss->le;
    tn->ln      = 0;
    tss->le->ln = tn;
    tss->le     = tn;

    return true;
}


struct tcp_stream*
ht_search(struct ts_storage *tss, struct tcp_stream *ts)
{
    struct ts_node  *iter   = 0;

    if(0 == tss || 0 == ts) return 0;

    unsigned int    hi  = hash_index(ts);

    // empty
    if(0 == tss->ht[hi]) return 0;

    iter    = tss->ht[hi];
    // hash list not empty
    while( iter && !ts_equal(&(iter->tstream), ts) )
        iter    = iter->hn;

    return iter ? &(iter->tstream) : 0;
}


unsigned int
do_tss_insert(struct ts_storage *tss, void *pi)
{
    struct tcp_stream   ts      = {0};
    struct ts_node      *inode  = 0;

    if(0 == tss || 0 == pi || 0 == get_tcp_hdr(pi) || 0 == get_ip_hdr(pi))
        return false;

    ts.client_ip    = get_ip_hdr(pi)->saddr;
    ts.server_ip    = get_ip_hdr(pi)->daddr;
    ts.client_port  = get_tcp_hdr(pi)->source;
    ts.server_port  = get_tcp_hdr(pi)->dest;

    // alread in the storage
    if(ht_search(tss, &ts)) return false;

    inode   = tn_malloc();
    if(0 == inode) return false;
    memcpy(&(inode->tstream), &ts, sizeof(struct tcp_stream));

    // todo: if failed, release the node
    return ht_insert(tss, inode) && li_add_to_end(tss, inode);
}


unsigned int
tss_insert(void *tss, void *pi)
{
    return do_tss_insert((struct ts_storage*)tss, pi);
}


struct tcp_stream*
do_tss_search(struct ts_storage *tss, void *pi)
{
    struct tcp_stream   ts      = {0};
    struct ts_node      *inode  = 0;

    if(0 == tss || 0 == pi || 0 == get_tcp_hdr(pi) || 0 == get_ip_hdr(pi))
        return false;

    ts.client_ip    = get_ip_hdr(pi)->saddr;
    ts.server_ip    = get_ip_hdr(pi)->daddr;
    ts.client_port  = get_tcp_hdr(pi)->source;
    ts.server_port  = get_tcp_hdr(pi)->dest;

    return ht_search(tss, &ts);
}


unsigned int
tss_search(void *tss, void *pi)
{
#if 0
    struct ts_storage   *t      = tss;
    struct ts_node      *node   = 0;
    struct ts_node      *node2  = 0;
    if(!t) return false;
    // _MESSAGE_OUT("============================\n");
    for(node = t->lr; node ; node = node->ln)
    {
        struct tcp_stream   *ts = &(node->tstream);
        // _MESSAGE_OUT("%-15s : %u ---> ", _netint32toip(ts->client_ip), _ntoh16(ts->client_port));
        // _MESSAGE_OUT("%-15s : %u\n", _netint32toip(ts->server_ip), _ntoh16(ts->server_port));
        // _MESSAGE_OUT("node : %p node->ln : %p\n", node, node->ln);
        for(node2 = node->ln; node2 ; node2 = node2->ln)
        {
            // _MESSAGE_OUT("\tnode2 : %p node2->ln : %p\n", node2, node2->ln);
            struct tcp_stream   *ts2 = &(node2->tstream);
            if(ts_equal(ts, ts2))
            {
                _MESSAGE_OUT("wtf?????????????????\n");
            }
        }
    }
#endif

    return do_tss_search((struct ts_storage*)tss, pi) ? true : false;
}


unsigned int
tss_add_s2c_data_size(void *tss, void *pi, unsigned int add_data_size)
{
    struct tcp_stream   *ts = do_tss_search(tss, pi);
    if(0 == ts) return false;

    ts->s2c_insert_start_seq    = _ntoh32(get_tcp_hdr(pi)->seq);

    ts->s2c_insert_data_size    = add_data_size;
    return true;
}


unsigned int
tss_s2c_data_size(void *tss, void *pi)
{
    struct tcp_stream   *ts = do_tss_search(tss, pi);

    return ts ? ts->s2c_insert_data_size : 0;
}


unsigned int
tss_s2c_insert_start_seq(void *tss, void *pi)
{
    struct tcp_stream   *ts = do_tss_search(tss, pi);

    return ts ? ts->s2c_insert_start_seq : 0;
}







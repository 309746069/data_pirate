#include "packet_wrapper.h"

#include "common.h"



struct packet_wrapper
{
    unsigned char           *packet;
    unsigned int            pkt_len;

    unsigned long long int  pkt_index;

    struct timeval          cap_time;
    struct timeval          send_time;
};


void
pw_free(struct packet_wrapper *pw)
{
    if(pw)
    {
        if(pw->packet)
        {
            free(pw->packet);
        }
        free(pw);
    }
}


struct packet_wrapper*
pw_malloc(unsigned int size)
{
    struct packet_wrapper   *pw = 0;
    pw  = malloc(sizeof(struct packet_wrapper));

    if(0 == pw)
    {
        return 0;
    }

    memset(pw, 0, sizeof(struct packet_wrapper));
    pw->packet  = malloc(size);
    if(0 == pw->packet)
    {
        pw_free(pw);
        return 0;
    }

    memset(pw->packet, 0, size);

    return pw;
}


void*
pw_create(  unsigned char   *pkt,
            unsigned int    pkt_len,
            struct timeval  *cap_time)
{
    static unsigned long long int   index   = 0;
    struct packet_wrapper           *pw     = 0;

    if(0 == pkt || 0 == pkt_len || 0 == cap_time)
    {
        goto failed_return;
    }

    pw  = pw_malloc(pkt_len);
    if(0 == pw)
    {
        goto failed_return;
    }

    memcpy(pw->packet, pkt, pkt_len);
    pw->pkt_len     = pkt_len;
    pw->pkt_index   = index;
    memcpy(&(pw->cap_time), cap_time, sizeof(struct timeval));

success_return:
    index ++;
    return pw;

failed_return:
    return 0;
}


void
pw_destory(void *pw)
{
    pw_free((struct packet_wrapper*)pw);
}


unsigned int
pw_get_pkt_len(void *pw)
{
    return pw ? ((struct packet_wrapper*)pw)->pkt_len : 0;
}


unsigned char*
pw_get_packet(void *pw)
{
    return pw ? ((struct packet_wrapper*)pw)->packet : 0;
}


void
pw_set_send_time(void *pw)
{
    if(0 == pw)
    {
        return;
    }

    gettimeofday((&((struct packet_wrapper*)pw)->send_time), 0);
}


unsigned long int
pw_get_spent_microsecond(void *pw)
{
    struct packet_wrapper   *p  = pw;
    if(0 == pw)
    {
        return 0;
    }

    if(p->send_time.tv_usec < p->cap_time.tv_usec)
    {
        return p->send_time.tv_usec + 1000*1000 - p->cap_time.tv_usec;
    }

    return p->send_time.tv_usec - p->cap_time.tv_usec;
}


unsigned long int
pw_get_spent_second(void *pw)
{
    struct packet_wrapper   *p  = pw;
    if(0 == pw)
    {
        return 0;
    }

    if(p->send_time.tv_usec < p->cap_time.tv_usec)
    {
        return p->send_time.tv_sec - p->cap_time.tv_sec - 1;
    }

    return p->send_time.tv_sec - p->cap_time.tv_sec;
}







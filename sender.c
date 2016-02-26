#include "sender.h"

#include <libnet.h>
#include <pthread.h>

#include "common.h"


// todo: 线程安全考虑 最好用多线程无锁队列
#define _LOCK
#ifdef _LOCK
pthread_mutex_t     mut;
#endif
libnet_t    *nd                                 = 0;
char        sender_errbuf[LIBNET_ERRBUF_SIZE]   = {0};




int
sender_initialize(const char* interface, char** return_err)
{
    *sender_errbuf = 0;

    if(return_err)
    {
        *return_err = sender_errbuf;
    }

    nd  = libnet_init(LIBNET_LINK_ADV, interface, sender_errbuf);
#ifdef _LOCK
    pthread_mutex_init(&mut, 0);
#endif

    if(0 == nd)
    {
        return false;
    }

    return true;
}


int
sender_send(const unsigned char* packet, const unsigned int size)
{
    int sent_size   = 0;
#ifdef _LOCK
    pthread_mutex_lock(&mut);
#endif
    sent_size   = libnet_adv_write_link(nd, packet, size);
#ifdef _LOCK
    pthread_mutex_unlock(&mut);
#endif

    if(-1 == sent_size || sent_size != size)
    {
        return false;
    }

    return true;
}


void
sender_finish(void)
{
    libnet_destroy(nd);
#ifdef _LOCK
    pthread_mutex_destroy(&mut);
#endif
}





















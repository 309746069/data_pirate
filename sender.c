#include "sender.h"

#include <libnet.h>

#include "common.h"


// todo: 线程安全考虑


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

    sent_size   = libnet_adv_write_link(nd, packet, size);

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
}





















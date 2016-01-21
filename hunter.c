#include "hunter.h"

#include <pthread.h>
#include <pcap.h>

#include "common.h"



struct pcap_t   *pd                             = 0;
char            hunter_errbuf[PCAP_ERRBUF_SIZE] = {0};
pthread_t       hunter                          = 0;


struct package_info
{
    unsigned char   *packet;
    unsigned int    size;
};

void*
thread_sender(void* arg)
{
    struct package_info *pi     = (struct package_info*)arg;
    struct _ethhdr      *eth    = (struct _ethhdr*)pi->packet;
    struct _iphdr       *ip     = 0;

    if(0 == strncmp(eth->h_source, "\x24\x24\x0e\x41\x58\xc7", 6))
    {
        _MESSAGE_OUT("there it is \n");
        memcpy(eth->h_dest, "\xd8\x15\x0d\x8c\x04\xfe", 6);
        if(false == _SEND_PACKAGE(pi->packet, pi->size))
            _MESSAGE_OUT("wtf???\n");
    }
    // free(pi->packet);
    free(pi);
}



void
packet_dispatch(    u_char                      *userarg,   // callback args
                    const struct pcap_pkthdr    *pkthdr,    // packet info
                    const u_char                *packet)    // packet buf
{
    static unsigned int i           = 0;
    // unsigned char       p[65535]    = {0};
    pthread_t           t           = 0;
    int                 err         = 0;
    struct _ethhdr      *eth        = 0;
    struct _iphdr       *ip         = 0;

    // _MESSAGE_OUT("[%05u] -> size : %d\n", i++, pkthdr->len);

    struct package_info *p  = malloc(sizeof(struct package_info));
    p->packet   = packet;
    p->size     = pkthdr->len;


    err = pthread_create(&t, 0, thread_sender, p);
    if(err)
    {
        _MESSAGE_OUT("pthread_create failed : %s\n", strerror(err));
    }
    return;

    if( _ntoh16(_ETH_P_IP) != eth->h_proto) return;

    ip  = packet + sizeof(struct _ethhdr);

    _MESSAGE_OUT("%s", _netint32toip(ip->saddr));
    _MESSAGE_OUT("\t-> %s\r\n", _netint32toip(ip->daddr));
    
    printf("%08x  %08x\n", _iptonetint32("192.168.1.104"), ip->saddr );

    if( _iptonetint32("192.168.1.104") == ip->saddr)
    {
        _MESSAGE_OUT("there it is\n");
        memcpy(p, packet, pkthdr->len);
        eth = (struct _ethhdr*)p;
        memcpy(eth->h_dest, "\xd8\x15\x0d\x8c\x04\xfe", 6);

        if(false == _SEND_PACKAGE(p, pkthdr->len))
            _MESSAGE_OUT("wtf???\n");

    }
}


void*
hunter_loop_thread(void* args)
{
    _MESSAGE_OUT("[+] hunter start!\n");
    pcap_loop(pd, -1, packet_dispatch, 0);
    _MESSAGE_OUT("[-] hunter stop!\n");
    return 0;
}


int
hunter_initialize(const char* interface, char** return_err)
{
    int     err         = 0;
    char*   notempty    = "initialize failed, hunter notempty!";

    *hunter_errbuf = 0;

    if(return_err)
    {
        *return_err  = hunter_errbuf;
    }

    if(hunter)
    {
        memcpy(hunter_errbuf, notempty, strlen(notempty));
        return false;
    }

    pd  = pcap_open_live(interface, 65535, 0, 1, hunter_errbuf);
    if(0 == pd)
    {
        return false;
    }

    err = pthread_create(&hunter, 0, hunter_loop_thread, 0);
    if(err)
    {
        memcpy(hunter_errbuf, strerror(err), strlen(strerror(err)));
        return false;
    }

    return true;
}


void
hunter_finish(void)
{
    if(hunter && pd)
    {
        pcap_breakloop(pd);
        pthread_join(hunter, 0);
        pcap_close(pd);
        hunter  = 0;
        pd      = 0;
    }
}





#include "hunter.h"

#include <pthread.h>
#include <pcap.h>

#include "common.h"
#include "net_state.h"
#include "router.h"



struct pcap_t   *pd                             = 0;
char            hunter_errbuf[PCAP_ERRBUF_SIZE] = {0};
pthread_t       hunter                          = 0;



void
packet_catcher( u_char                      *userarg,   // callback args
                const struct pcap_pkthdr    *pkthdr,    // packet info
                const u_char                *packet)    // packet buf
{
    router(packet, pkthdr->len, &(pkthdr->ts));
}


void*
hunter_loop_thread(void* args)
{
    _MESSAGE_OUT("[+] hunter start!\n");
    pcap_loop(pd, -1, packet_catcher, 0);
    _MESSAGE_OUT("[-] hunter stop!\n");
    return 0;
}


int
hunter_start(const char* interface, char** return_err)
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
hunter_stop(void)
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





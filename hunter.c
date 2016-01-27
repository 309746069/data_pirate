#include "hunter.h"

#include <pthread.h>
#include <pcap.h>

#include "common.h"
#include "net_state.h"



struct pcap_t   *pd                             = 0;
char            hunter_errbuf[PCAP_ERRBUF_SIZE] = {0};
pthread_t       hunter                          = 0;



void
packet_dispatch(    u_char                      *userarg,   // callback args
                    const struct pcap_pkthdr    *pkthdr,    // packet info
                    const u_char                *packet)    // packet buf
{
    struct _ethhdr      *eth        = (struct _ethhdr*)packet;
    struct hostent      *hi          = 0;

    // send by us, return;
    if( 0 == memcmp(eth->h_source, my_mac_address(), 6) )
    {
        return;
    }




    if(_ntoh16(_ETH_P_ARP) == eth->h_proto)
    {
        struct _arphdr  *arp    = packet + sizeof(struct _ethhdr);
        unsigned int    ip      = 0;
        memcpy(&ip, arp->ar_sip, 4);

        printf("%14s is at %02X:%02X:%02X:%02X:%02X:%02X\n",
                _netint32toip(ip),
                arp->ar_sha[0], arp->ar_sha[1], arp->ar_sha[2], 
                arp->ar_sha[3], arp->ar_sha[4], arp->ar_sha[5] );
        
        set_host_info(ip, arp->ar_sha, pkthdr->ts.tv_sec);

    }

    return;





    static unsigned int i           = 0;
    unsigned char       p[65535]    = {0};
    pthread_t           t           = 0;
    int                 err         = 0;

    struct _iphdr       *ip         = 0;


    char    str[3000]    = {0};
    int     len         = 0;
    if(i <= 0xffffffff)
    {
        sprintf(str, "[%08u]->%u\n", i++, pkthdr->len);
        // queue_write_message(arpqueue, str, strlen(str) + pkthdr->len, 0);
    }
    else
    {
        _MESSAGE_OUT("======================================write end\n");
        // queue_write_end(arpqueue);
    }

    // if(_ntoh16(_ETH_P_ARP) == eth->h_proto)
    // {
    //     char*   str =  "arp package\n";
    //     queue_write_message(arpqueue, str, strlen(str), 0);
    // }
    // _MESSAGE_OUT("[%05u] -> size : %d\n", i++, pkthdr->len);
    // memcpy(p, packet, pi.size);

    // thread_sender((void*)&pi);return;
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





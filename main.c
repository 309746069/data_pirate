#include <stdio.h>

#include <pcap.h>
#include <libnet.h>

#include "data_pirate.h"
#include "sender.h"
#include "net_state.h"

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


int
main(const int argc, const char* argv[])
{
    int         err     = 0;
    pthread_t   hunter  = 0;
    char*       perr    = 0;
    char        buf[1024]   = {0};


    if(false == initialize(argc, argv))
    {
        return -1;
    }


    while(1) sleep(1);

    if(false == finish())
    {
        return -1;
    }

    return 0;
}













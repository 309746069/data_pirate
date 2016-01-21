#include <stdio.h>

#include <pcap.h>
#include <libnet.h>

#include "robber.h"
#include "hunter.h"
#include "sender.h"

#define INTERFACE   "en0"



int
finish(void)
{
    hunter_finish();
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

    signal(SIGINT, signal_handler);     // ctrl+c handler

    if(false == sender_initialize(INTERFACE, &perr))
    {
        _MESSAGE_OUT("%s\n", perr);
        return false;
    }

    return true;
}




int
main(const int argc, const char* argv[])
{
    int         err     = 0;
    pthread_t   hunter  = 0;
    char*       perr    = 0;



    if(false == initialize(argc, argv))
    {
        return -1;
    }

    if(false == hunter_initialize(INTERFACE, &perr))
    {
        _MESSAGE_OUT("[!] hunter_initialize failed! caused by : %s\n",         \
                        perr);
        return -1;
    }


    cheater_test();

    while(1) sleep(1);


    if(false == finish())
    {
        return -1;
    }

    return 0;
}













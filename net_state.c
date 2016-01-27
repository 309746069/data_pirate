#include "net_state.h"

#include <string.h>

#include "common.h"


// struct define ===============================================================
struct _device_info
{
    unsigned int        is_online;
    time_t              last_online_time;

    unsigned int        ip_netint32;
    unsigned char       mac[6];
    unsigned char       cheat_on;
    unsigned char       cheat_mode;
};

struct _net_state
{
    unsigned char       *net_interface;
    unsigned char       mac[6];
    unsigned int        ip_netint32;
    unsigned int        mask_netint32;
    unsigned int        ip_route_netint32;
    unsigned int        d_arr_max;
    struct _device_info *d_arr;
};


struct _net_state       *net_info   = 0;

// function ====================================================================
int
net_state_init( const unsigned char *interface,
                const unsigned char *mac,
                const unsigned int  ip_netint32,
                const unsigned int  mask_netint32,
                const unsigned int  ip_route_netint32)
{
    int len     = 0;

    if(!interface || !mac || !ip_netint32
         || !mask_netint32 || !ip_route_netint32)
    {
        _MESSAGE_OUT("[!] net_state_init failed, check network!\n");
        return false;
    }

    net_info    = malloc( sizeof(struct _net_state) );
    memset(net_info, 0, sizeof(struct _net_state));

    len                     = strlen(interface);
    net_info->net_interface = malloc(len + 1);
    memset(net_info->net_interface, 0, len + 1);
    memcpy(net_info->net_interface, interface, len);

    memcpy(net_info->mac, mac, 6);

    net_info->ip_netint32       = ip_netint32;
    net_info->mask_netint32     = mask_netint32;
    net_info->ip_route_netint32 = ip_route_netint32;

    net_info->d_arr_max         = ~(_ntoh32(mask_netint32)) + 1;

    net_info->d_arr = malloc(sizeof(struct _device_info) * net_info->d_arr_max);
    memset(net_info->d_arr, 0, sizeof(struct _device_info)*net_info->d_arr_max);

    return true;
}


unsigned int
my_ip_netint32(void)
{
    return net_info->ip_netint32;
}


unsigned char*
my_mac_address(void)
{
    return net_info->mac;
}


unsigned char*
my_net_interface(void)
{
    return net_info->net_interface;
}


unsigned int
route_ip_netint32(void)
{
    return net_info->ip_route_netint32;
}


unsigned int
net_mask_netint32(void)
{
    return net_info->mask_netint32;
}


unsigned int
device_max(void)
{
    return net_info->d_arr_max;
}


unsigned int
device_index(unsigned int ip_netint32)
{
    return _ntoh32( ip_netint32 & (~(net_mask_netint32())) );
}


unsigned int
is_device_online(unsigned int ip_netint32)
{
    return ip_netint32 ?
        net_info->d_arr[device_index(ip_netint32)].is_online : false;
}


unsigned int
set_host_info(unsigned int ip_netint32, unsigned char *mac, time_t reply_time)
{
    struct _device_info *di = 0;

    if(0 == ip_netint32 || 0 == mac)
    {
        return false;
    }

    di  = net_info->d_arr + device_index(ip_netint32);

    memcpy(di->mac, mac, 6);

    di->last_online_time    = reply_time;
    di->ip_netint32         = ip_netint32;
    di->is_online           = true;

    return true;
}


unsigned char*
device_mac_address(unsigned int ip_netint32)
{
    return ip_netint32 ? 
        net_info->d_arr[device_index(ip_netint32)].mac : false;
}


time_t
device_last_online_time(unsigned int ip_netint32)
{
    return ip_netint32 ? 
        net_info->d_arr[device_index(ip_netint32)].last_online_time : 0;
}

unsigned int
merge_device_index_to_ip_netint32(unsigned int device_index)
{
    return my_ip_netint32() & net_mask_netint32() | _ntoh32(device_index);
}


void
set_cheat_mode(unsigned int ip_netint32, unsigned int mode)
{
    net_info->d_arr[device_index(ip_netint32)].cheat_mode   = mode;
}


void
set_cheat_on(unsigned int ip_netint32)
{
    if(ip_netint32)
    {
        net_info->d_arr[device_index(ip_netint32)].cheat_on = 10;
    }
}


void
set_cheat_off(unsigned int ip_netint32)
{
    if(ip_netint32)
    {
        net_info->d_arr[device_index(ip_netint32)].cheat_on = 9;
    }
}


void
set_cheat_state_clean(unsigned int ip_netint32)
{
    if(ip_netint32)
    {
        net_info->d_arr[device_index(ip_netint32)].cheat_on = 0;
    }
}


int
get_cheat_state(unsigned int ip_netint32)
{    
    if(0 == ip_netint32)
    {
        return CHEAT_OFF;
    }

    if(0 == net_info->d_arr[device_index(ip_netint32)].cheat_on)
    {
        return CHEAT_OFF;
    }

    if(10 == net_info->d_arr[device_index(ip_netint32)].cheat_on)
    {
        return CHEAT_ON;
    }

    if(10 > net_info->d_arr[device_index(ip_netint32)].cheat_on)
    {
        net_info->d_arr[device_index(ip_netint32)].cheat_on -- ;
        return CHEAT_DELAY;
    }
}


unsigned char
get_cheat_mode(unsigned int ip_netint32)
{
    return net_info->d_arr[device_index(ip_netint32)].cheat_mode;
}


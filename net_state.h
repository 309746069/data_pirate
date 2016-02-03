#pragma once
#include <sys/time.h>

#define CHEAT_OFF           0
#define CHEAT_ON            1
#define CHEAT_DELAY         2

#define CHEAT_MODE_MITM     0
#define CHEAT_MODE_TARGET   1

// init ========================================================================
int
net_state_init( const unsigned char *interface,
                const unsigned char *mac,
                const unsigned int  ip_netint32,
                const unsigned int  mask_netint32,
                const unsigned int  ip_route_netint32);


// write =======================================================================
unsigned int
set_host_info(unsigned int ip_netint32, unsigned char *mac, time_t reply_time);

void
set_cheat_on(unsigned int ip_netint32);

void
set_cheat_off(unsigned int ip_netint32);

void
set_cheat_state_clean(unsigned int ip_netint32);

void
set_cheat_mode(unsigned int ip_netint32, unsigned int mode);

// read ========================================================================
unsigned int
my_ip_netint32(void);

unsigned char*
my_mac_address(void);

unsigned char*
my_net_interface(void);

unsigned int
route_ip_netint32(void);

unsigned int
net_mask_netint32(void);

unsigned int
device_max(void);

unsigned int
is_device_online(unsigned int ip_netint32);

unsigned char*
device_mac_address(unsigned int ip_netint32);

time_t
device_last_online_time(unsigned int ip_netint32);

unsigned int
merge_device_index_to_ip_netint32(unsigned int device_index);

int
get_cheat_state(unsigned int ip_netint32);

unsigned char
get_cheat_mode(unsigned int ip_netint32);

int
is_target_in_LAN(unsigned int ip_netint32);

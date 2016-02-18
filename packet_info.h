#pragma once

#include <sys/time.h>


void*
pi_create(  unsigned char   *packet,
            unsigned int    pkt_len,
            struct timeval  *cap_time);

int
pi_set_pkt_len(void *pi, unsigned int len);

void
pi_destory(void *pi);

unsigned char*
get_pkt_ptr(void *pi);

unsigned int
get_pkt_len(void *pi);

struct _ethhdr*
get_eth_hdr(void *pi);

struct _arphdr*
get_arp_hdr(void *pi);

struct _iphdr*
get_ip_hdr(void *pi);

struct _tcphdr*
get_tcp_hdr(void *pi);

unsigned char*
get_tcp_data_ptr(void *pi);

unsigned int
get_tcp_data_len(void *pi);

unsigned char*
get_http_ptr(void *pi);

unsigned int
get_http_hdr_len(void *pi);


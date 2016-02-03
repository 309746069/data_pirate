#pragma once

#include <sys/time.h>

void*
pw_create(  unsigned char   *pkt,
            unsigned int    pkt_len,
            struct timeval  *cap_time);

void
pw_destory(void *pw);

unsigned int
pw_get_pkt_len(void *pw);

unsigned char*
pw_get_packet(void *pw);

void
pw_set_send_time(void *pw);

unsigned long int
pw_get_spent_second(void *pw);

// microsecond = 1/1000 millisecond == 1/(1000*1000)second
unsigned long int
pw_get_spent_microsecond(void *pw);
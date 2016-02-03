#pragma once
#include <sys/time.h>


void
robber( const unsigned char*    packet,
        const unsigned int      pkt_len,
        const struct timeval    *cap_time);
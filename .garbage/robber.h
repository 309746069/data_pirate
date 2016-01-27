#pragma once
#include "common.h"

#define __PKG_ACCEPT__                  0
#define __PKG_CHANGE__                  1

// like sk_buff, package analysiser ============================================



struct http_package_info
{
    unsigned char*      pkg_ptr;
    unsigned int        pkg_size;   // byte;
    struct _ethhdr      *eth;
    struct _iphdr       *ip;
    struct _tcphdr      *tcp;
    unsigned char       *http;

    unsigned char       s2c;
};



unsigned int robber(void* __pkg, unsigned int __pkg_size);

unsigned int http_robber(void* __pkg, unsigned int __pkg_size);
















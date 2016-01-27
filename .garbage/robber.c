#include "robber.h"


// #define _DEBUG_LOG



unsigned int
get_tcp_date_len(struct http_package_info *p)
{
    unsigned char   *end    = p->pkg_ptr + p->pkg_size; 

    return end <= p->http ? 0 : end - p->http;
}


unsigned int
get_http_header_len(struct http_package_info *p)
{
    return 0;
}


int
is_http_pkg(struct http_package_info *p)
{
    p->eth  = (struct _ethhdr*)p->pkg_ptr;

    if(_ETH_P_IP != p->eth->h_proto)
    {
        return FALSE;
    }

    p->ip   = (struct _iphdr*)( (char*)p->eth + sizeof(struct _ethhdr) );

    if(_IPPROTO_TCP != p->ip->protocol)
    {
        return FALSE;
    }

    p->tcp  = (struct _tcphdr*)( (char*)p->ip + p->ip->ihl * 4 );

    if(_PORT_80 == p->tcp->dest)
    {
        p->s2c  = FALSE;
    }
    else if(_PORT_80 == p->tcp->source)
    {
        p->s2c  = TRUE;
    }
    else
    {
        return FALSE;
    }

    p->http   = (unsigned char*)( (char*)p->tcp + p->tcp->doff * 4);

    return TRUE;
}



unsigned int
http_robber(void* __pkg, unsigned int __pkg_size)
{
    unsigned int                    ret = __PKG_ACCEPT__;
    static struct http_package_info hpi = {0};
    static struct http_package_info *p  = &hpi;

    // duff_memclr(&hpi, sizeof(struct http_package_info));
    memset(p, 0, sizeof(struct http_package_info));

    hpi.pkg_ptr     = __pkg;
    hpi.pkg_size    = __pkg_size;

    if(FALSE == is_http_pkg(p))
    {
        return __PKG_ACCEPT__;
    }

    static int i=0;
    i++;
    _DEBUG_LOG("============%d", i);
    _SEND_PACKAGE(p->pkg_ptr, p->pkg_size);
    _DEBUG_LOG("%p", p->pkg_ptr);



    return ret;
}



unsigned int
robber(void* __pkg, unsigned int __pkg_size)
{
    return http_robber(__pkg, __pkg_size);
}
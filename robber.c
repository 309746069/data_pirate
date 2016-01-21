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




#ifdef ___DEBUG__
void
output_crlf_ex(char* pointer, unsigned int len)
{
    int i   = 0;
    static char out[1500] = {0};

    if(!len) return;

    memset(out, 0, 1500);
    memcpy(out, pointer, len);

    // remove "\x0a"
    for(i=0; i<len; i++)
        out[i] = out[i] == 0x0a ? 0:out[i];

    for(i=0; i<len; )
    {
        if(0 == out[i]) 
        {
            i++;
            continue;
        }

        _DEBUG_LOG("%s", out + i);
        i += strlen(out+i);
    }
}


void
http_pkg_test_log_out(struct http_package_info *p)
{
    static char out_put_buf[1500]   = {0};
    // duff_memclr(out_put_buf, 1500);
    memset(out_put_buf, 0, 1500);


    _DEBUG_LOG("=============================================================");

    _DEBUG_LOG("%04x : %02x -> %04x : %02x", 
                    p->ip->saddr, p->tcp->source, 
                    p->ip->daddr, p->tcp->dest);

    _DEBUG_LOG("tcp_date_len : %d", get_tcp_date_len(p));

    // duff_memcpy(out_put_buf, p->http, get_tcp_date_len(p));
    // _DEBUG_LOG("%s", out_put_buf);
    output_crlf_ex(p->http, get_tcp_date_len(p));
}
#endif





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

#ifdef ___DEBUG__
    http_pkg_test_log_out(p);
#endif
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
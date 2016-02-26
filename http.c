#include "http.h"

#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "router.h"
#include "packet_info.h"
#include "gzip_wrapper.h"
#include "tcp_stream.h"



int one_shot_init(void *pi);

void    *tss    = 0;

int (*http_handle_fun)(void*) = one_shot_init;


void*
memsearch(  unsigned char *mem, unsigned int mem_len,
            unsigned char *tar, unsigned int tar_len)
{
    if(0 == mem || 0 == mem_len || 0 == tar || 0 == tar_len) return 0;
    if(mem_len < tar_len) return 0;

    if(mem_len == tar_len && 0 == memcmp(mem, tar, tar_len))
        return mem;

    void    *ret_ptr    = 0;
    int     i           = 0;

    for(i=0; i<mem_len-tar_len; i++)
    {
        ret_ptr = mem + i;
        if(0 == memcmp(ret_ptr, tar, tar_len)) return ret_ptr;
    }

    return 0;
}


unsigned int
mem_change_long_to_short(   unsigned char *buf, unsigned int buf_len,
                            unsigned char *src, unsigned int src_len,
                            unsigned char *dst, unsigned int dst_len)
{
    if(!buf || !buf_len || !src || !src_len || !dst || !dst_len)
        return false;

    if(dst_len > src_len) return false;
    if(src_len > buf_len) return false;

    unsigned char   *tar    = memsearch(buf, buf_len, src, src_len);
    if(!tar) return false;

    memcpy(tar, dst, dst_len);
    if(src_len > buf_len)
    {
        int i = 0;
        for(i=0; tar+dst_len+i<=buf+buf_len; i++)
            *(tar+dst_len+i)    = *(tar+src_len+i);
    }
    return true;
}


unsigned int
delete_pkt_data(void *pi, unsigned char *from, unsigned int size)
{
    unsigned int    pkt_len = get_pkt_len(pi);
    unsigned char   *pkt    = get_pkt_ptr(pi);

    if(pkt > from || pkt_len <= size)
    {
        return false;
    }

    unsigned int    len     = pkt + pkt_len - (from + size);

    // just in case
    unsigned char   buf[PACKET_BUFSIZE] = {0};
    memcpy(buf, from + size, len);
    memset(from, 0, len + size);
    memcpy(from, buf, len);

    // fix ip->tot_len
    get_ip_hdr(pi)->tot_len = _ntoh16(_ntoh16(get_ip_hdr(pi)->tot_len) - size);
    // fix pkt_len
    pi_set_pkt_len(pi, pkt_len - size);

    return true;
}


unsigned int
h_hdr_delete_line(void *pi, unsigned char *delete_line)
{
    while(true)
    {
        unsigned char   *http   = get_http_ptr(pi);
        unsigned int    hdr_len = get_http_hdr_len(pi);

        if(0 == http || 0 == hdr_len) return false;

        unsigned char   *p      = 0;
        unsigned char   *pend   = 0;

        p   = strnstr(http, delete_line, hdr_len);
        if(0 == p) break;

        pend    = strnstr(p, "\r\n", hdr_len - (p-http));
        if(0 == pend) return false;

        if(false == delete_pkt_data(pi, p, pend-p + 2)) return false;
    }

    return true;
}


// add_line include "\r\n"
unsigned int
h_hdr_add_line(void *pi, unsigned char *add_line)
{
    unsigned char   *http   = get_http_ptr(pi);
    unsigned int    hdr_len = get_http_hdr_len(pi);
    unsigned char   *pkt    = get_pkt_ptr(pi);
    unsigned int    pkt_len = get_pkt_len(pi);
    unsigned int    a_len   = strlen(add_line);

    if(0 == http || 0 == hdr_len || a_len + pkt_len > 1500) return false;

    unsigned char   buf[PACKET_BUFSIZE] = {0};
    unsigned char   *insert_start   = http + hdr_len - 2;

    memcpy(buf, insert_start, pkt + pkt_len - insert_start);
    memcpy(insert_start, add_line, a_len);
    memcpy(insert_start + a_len, buf, pkt + pkt_len - insert_start);

    // fix ip->tot_len
    get_ip_hdr(pi)->tot_len = _ntoh16(a_len + _ntoh16(get_ip_hdr(pi)->tot_len));

    // fix pkt_len
    pi_set_pkt_len(pi, pkt_len + a_len);

    return true;
}


unsigned int
fix_content_length(void *pi, int offset)
{
    unsigned char   *http   = get_http_ptr(pi);
    unsigned int    hdr_len = get_http_hdr_len(pi);

    if(!http || !hdr_len) return false;

    unsigned char   *cl     = strnstr(http, "Content-Length:", hdr_len);
    int             len     = 0;
    sscanf(cl, "Content-Length: %d", &len);
    // todo : overflow
    len += offset;
    sprintf(cl, "Content-Length: %d", len);

    return true;
}



unsigned int
comfort_my_baby(void *pi)
{
    int             c2s_offset  = 0;
    int             s2c_offset  = 0;
    unsigned int    abs_offset  = 0;
    unsigned int    start_seq   = 0;
    unsigned int    seq_tmp     = 0;
    unsigned int    is_c2s      = tss_is_client_to_server(tss, pi);
    struct _tcphdr  *tcp        = get_tcp_hdr(pi);

    if(0 == tcp) return false;

    // client to server data insert fix
    c2s_offset = tss_c2s_data_size(tss, pi);
    if(0 != c2s_offset)
    {
        abs_offset  = abs(c2s_offset);
        start_seq   = tss_c2s_insert_start_seq(tss, pi);
        // fix
        // client to server
        if(is_c2s)
        {
            seq_tmp = _ntoh32(tcp->seq);
            if(seq_tmp > start_seq)
            {
                seq_tmp     = (   (c2s_offset > 0)
                                ? (seq_tmp + abs_offset)
                                : (seq_tmp - abs_offset) );
                tcp->seq    = _ntoh32(seq_tmp);
            }
        }
        // server to client
        else
        {
            seq_tmp = _ntoh32(tcp->ack_seq);
            if(seq_tmp > start_seq)
            {
                seq_tmp         = (   (c2s_offset > 0)
                                    ? (seq_tmp - abs_offset)
                                    : (seq_tmp + abs_offset) );
                tcp->ack_seq    = _ntoh32(seq_tmp);
            }
        }
    }


    // server to client data insert fix
    s2c_offset = tss_s2c_data_size(tss, pi);
    if(0 != s2c_offset)
    {
        // _MESSAGE_OUT("s2c_offset : %d", s2c_offset);
        abs_offset  = abs(s2c_offset);
        start_seq   = tss_s2c_insert_start_seq(tss, pi);
        // fix
        // client to server
        if(is_c2s)
        {
            seq_tmp = _ntoh32(tcp->ack_seq);
            // _MESSAGE_OUT("client to server : fix ack_seq %10u", seq_tmp);

            // todo : when seq overflow, stream will crash
            if(seq_tmp > start_seq)
            {
                seq_tmp         = (   (s2c_offset > 0)
                                    ? (seq_tmp - abs_offset)
                                    : (seq_tmp + abs_offset) );
                tcp->ack_seq    = _ntoh32(seq_tmp);
            }
            // _MESSAGE_OUT(" to %10u\n", seq_tmp);
        }
        // server to client
        else
        {
            seq_tmp = _ntoh32(tcp->seq);
            // _MESSAGE_OUT("server to client : fix seq %10u", seq_tmp);

            // todo : when seq overflow, stream will crash
            if(seq_tmp > start_seq)
            {
                seq_tmp     = (   (s2c_offset > 0)
                                ? (seq_tmp + abs_offset)
                                : (seq_tmp - abs_offset) );
                tcp->seq    = _ntoh32(seq_tmp);
            }
            // _MESSAGE_OUT(" to %10u\n", seq_tmp);
        }
    }

    if(s2c_offset || c2s_offset)
    {
        tcp_checksum(pi);
    }

    return true;
}


unsigned int
is_my_girl(void *pi)
{
    return tss_search(tss, pi);
}


void
http_hdr_logout(void *pi)
{
    unsigned char   *http   = get_http_ptr(pi);
    unsigned int    hdr_len = get_http_hdr_len(pi);

    if(!http || !hdr_len)
        _MESSAGE_OUT("[!]no http header\n");

    unsigned char   out[1800]   = {0};
    memcpy(out, http, hdr_len);
    _MESSAGE_OUT("===========================\n%s", out);
}



unsigned int
open_beautiful_legs_and_do_fuck(void *pi)
{
    unsigned char   *http   = get_http_ptr(pi);
    unsigned int    hdr_len = get_http_hdr_len(pi);
    unsigned char   *tdp    = get_tcp_data_ptr(pi);
    unsigned int    td_len  = get_tcp_data_len(pi);

    if(!http || !hdr_len || !tdp || !td_len) return false;

    unsigned char   *src    =
#if 0
    "type=\"text/javascript\">";
#else
    " <!DOCTYPE html>";
#endif
    unsigned int    src_len = strlen(src);
    unsigned char   *dst    =
#if 0
    ">alert(\"fuck\");        ";
#else
    "  ";
#endif
    unsigned int    dst_len = strlen(dst);
    unsigned int    diff    = src_len - dst_len;


    if(tss_s2c_data_size(tss, pi)) return false;

    http_hdr_logout(pi);
    if(mem_change_long_to_short(tdp, td_len, src, src_len, dst, dst_len))
    {
        unsigned int    pkt_len = get_pkt_len(pi);
        pi_set_pkt_len(pi, pkt_len - diff);
        tss_s2c_insert_data_size(tss, pi, get_pkt_len(pi) - pkt_len);
        fix_content_length(pi, get_pkt_len(pi)-pkt_len);
        tcp_checksum(pi);
        _MESSAGE_OUT("already in\n");
    }

    http_hdr_logout(pi);



    // if('H' == *http)
    // {
    //     unsigned int    pkt_len = get_pkt_len(pi);
    //     unsigned char   *p      = 0;
    //     unsigned int    len     = strlen("<!DOCTYPE html>");
    //     p   = strnstr(http,  "<!DOCTYPE html>", hdr_len);
    //     if(!p) return false;
    //     if(tss_s2c_data_size(tss, pi)) return false;
    //     tss_s2c_insert_data_size(tss, pi, get_pkt_len(pi) - pkt_len);
    //     tcp_checksum(pi);
    //     _MESSAGE_OUT("delete ........\n");
    // }

    return false;
}


unsigned int
follow_this_beauty(void *pi)
{
    struct _tcphdr  *tcp    = get_tcp_hdr(pi);
    if(0 == tcp) return false;

    return (_ntoh16(80) == tcp->dest)
            ? tss_c2s_insert(tss, pi)
            : tss_s2c_insert(tss, pi);
}


unsigned int
i_wanna_fuck_this_beauty(void *pi)
{
    unsigned char   *http   = get_http_ptr(pi);
    unsigned int    hdr_len = get_http_hdr_len(pi);

    if(0 == http || 0 == hdr_len) return false;

#if 1
    if('G' == *http && strnstr(http, "GET /ipad/ ", hdr_len))
    {
        http_hdr_logout(pi);
        unsigned int    pkt_len = get_pkt_len(pi);
        h_hdr_delete_line(pi, "Accept-Encoding:");
        h_hdr_delete_line(pi, "If-Modified-Since:");
        h_hdr_delete_line(pi, "If-None-Match:");

        // if(    false == h_hdr_delete_line(pi, "Accept-Encoding:")
        //     || false == h_hdr_delete_line(pi, "If-Modified-Since:") )
        // {
        //     return false;
        // }

        h_hdr_add_line(pi, "Accept-Encoding: none\r\n");

        // unsigned char   *p      = 0;
        // unsigned char   *pend   = 0;

        // p = strnstr(http, "Accept-Encoding:", hdr_len);
        // if(p)
        // {
        //     pend = strnstr(p, "\r\n", hdr_len - (p-http));
        //     if(pend)
        //     {
        //         memset(p, ' ', pend-p);
        //         memcpy(p, "Accept-Encoding: none", strlen("Accept-Encoding: none"));
        //     }
        // }

        // p = strnstr(http, "If-Modified-Since:", hdr_len);
        // if(p)
        // {
        //     pend = strnstr(p, "\r\n", hdr_len - (p-http));
        //     if(pend)
        //     {
        //         memset(p, ' ', pend-p);
        //     }
        // }


        tcp_checksum(pi);
        follow_this_beauty(pi);
        tss_c2s_insert_data_size(tss, pi, get_pkt_len(pi) - pkt_len);
        http_hdr_logout(pi);
        // unsigned char out[1800] = {0};
        // memcpy(out, http, hdr_len);
        // _MESSAGE_OUT("%s\n", out);
        // memset(out, 0, 1800);
        // memcpy(out, get_http_ptr(npi), get_http_hdr_len(npi));
        // _MESSAGE_OUT("%s\n=====================\n", out);
        return true;
    }
#else
    if('H' == *http
        && strnstr(http, "chunked", hdr_len))
    {
        int pkt_size    = get_pkt_len(pi);
        // h_hdr_delete_line(pi, "Expries:");
        h_hdr_delete_line(pi, "Server:");
        tcp_checksum(pi);
        follow_this_beauty(pi);
        tss_s2c_insert_data_size(tss, pi, (int)get_pkt_len(pi) - pkt_size);
        _MESSAGE_OUT("get it! delete_size : %d\n", (int)get_pkt_len(pi) - pkt_size);
        return true;
    }
#endif

    return false;
}


int
http_handler(void *pi)
{
    if(true == is_my_girl(pi))
    {
        comfort_my_baby(pi);
        open_beautiful_legs_and_do_fuck(pi);

        return PKT_ACCEPT;
    }
    else
    {
        i_wanna_fuck_this_beauty(pi);

        return PKT_ACCEPT;
    }
}


int
one_shot_init(void *pi)
{
    http_handle_fun = http_handler;

    // _MESSAGE_OUT("===========================one shot init!!!!!\n");
    while(!tss) tss = tss_create();

    return (*http_handle_fun)(pi);
}


int
http(void *pi)
{
    return (*http_handle_fun)(pi);
}


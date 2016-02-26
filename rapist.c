#include "rapist.h"

#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "packet_info.h"
#include "stalker.h"
#include "router.h"
#include "tcp_stream.h"


unsigned int rapist_one_shot_init(void *pi);

void    *tss    = 0;

int (*rapist_filter)(void*) = rapist_one_shot_init;



void
http_hdr_logout(void *pi)
{
    unsigned char   *http   = get_http_ptr(pi);
    unsigned int    hdr_len = get_http_hdr_len(pi);

    if(!http || !hdr_len)
        return;
        // _MESSAGE_OUT("[!]no http header\n");

    unsigned char   out[1800]   = {0};
    memcpy(out, http, hdr_len);
    _MESSAGE_OUT("===========================\n%s", out);
}


unsigned int
get_uri_from_pi(void *pi, unsigned char *retbuf, unsigned int bufsize)
{
    unsigned char   *http   = get_http_ptr(pi);

    unsigned char   buf[PACKET_BUFSIZE] = {0};

    if(0 == http || get_pkt_ptr(pi) + get_pkt_len(pi) < http) return false;

    if('G' == *http)
    {
        sscanf(http, "GET %s HTTP", buf);
        unsigned int    len = strlen(buf);

        if(bufsize >= len)
        {
            memcpy(retbuf, buf, len);
            return len;
        }
        // else
        // {
        //     memcpy(retbuf, buf, bufsize);
        //     return bufsize;
        // }
    }

    return false;
}


// in stalker thread ===========================================================
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
stalker_callback(void *si, void *pi)
{
    // comfort_my_baby(pi);

    // http_hdr_logout(pi);
    unsigned char   uri[PACKET_BUFSIZE] = {0};
    unsigned int    uri_len = get_uri_from_pi(pi, uri, PACKET_BUFSIZE);
    if(uri_len
// #if 1
//        && strnstr(uri, ".js", uri_len)
// #else
//        && !strnstr(uri, ".jpg", uri_len)
//        && !strnstr(uri, ".swf", uri_len)
//        && !strnstr(uri, ".png", uri_len)
//        && !strnstr(uri, ".mp4", uri_len)
// #endif
        )
        _MESSAGE_OUT("%s\n", uri);


    route_packet(pi);
    pi_destory(pi);
    return true;
}


// in router thread ============================================================
unsigned int
follow_this_beauty(void *pi)
{
    struct _tcphdr  *tcp    = get_tcp_hdr(pi);
    if(0 == tcp) return false;

    if( (_ntoh16(80) == tcp->dest)
            ? tss_c2s_insert(tss, pi)
            : tss_s2c_insert(tss, pi) )
    {
        void    *si = stalker_create();
        if(!si) return false;
        stalker_set_callback(si, stalker_callback);
        return tss_set_stalker(tss, pi, si);
    }

    return false;
}

unsigned int
fuck_my_baby(void *si, void *pi)
{
    return si ? stalker_push_new_ptr(si, pi) : false;
}


void*
is_my_girl(void *pi)
{
    return tss_get_stalker(tss, pi);
}


unsigned int
i_wanna_fuck_this_beauty(void *pi)
{
    // unsigned char   *http   = get_http_ptr(pi);
    // unsigned int    hdr_len = get_http_hdr_len(pi);
 
    // if(0 == http || 0 == hdr_len) return false;

    return true;
}


unsigned int
fuck_filter(void *pi)
{
    void    *stalker    = is_my_girl(pi);
    if(stalker)
    {
        return fuck_my_baby(stalker, pi);
    }

    else if(i_wanna_fuck_this_beauty(pi))
    {
        return follow_this_beauty(pi) && fuck_filter(pi);
    }

    return false;
}


unsigned int
rapist_one_shot_init(void *pi)
{
    rapist_filter = fuck_filter;

    // _MESSAGE_OUT("===========================one shot init!!!!!\n");
    while(!tss) tss = tss_create();

    return (*rapist_filter)(pi);
}


unsigned int
rapist(void *pi)
{
    return (*rapist_filter)(pi);
}

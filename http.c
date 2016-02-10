#include "http.h"

#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "router.h"
#include "packet_info.h"



int
http(void *pi)
{
    unsigned char   *http   = get_http_ptr(pi);

    if(get_http_hdr_len(pi))
    {
        // if('G' == *http || 'P' == *http)
        if('H' == *http)
        {
            unsigned char   out[1800]   = {0};
            memcpy(out, http, get_http_hdr_len(pi));
            if(strnstr(out, "chunked", 1800))
            _MESSAGE_OUT("========================================\n%s", out);
        }
    }


    return PKT_ACCEPT;
}

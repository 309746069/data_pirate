#include "http.h"

#include "router.h"
#include "rapist.h"


int
http_handler(void *pi)
{
    return rapist(pi) ? PKT_STOLEN : PKT_ACCEPT;
}


int
http(void *pi)
{
    return http_handler(pi);
}


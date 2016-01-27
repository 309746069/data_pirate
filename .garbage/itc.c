#include "itc.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "queue.h"
#include "common.h"


struct itc_double_queue
{
    void    *daddy2son; // daddy to son
    void    *son2daddy;
};


void*
itc_create(const unsigned int bufsize, unsigned char *return_err_buf)
{
    struct itc_double_queue     *itc    = 0;

    itc = malloc(sizeof( struct itc_double_queue ));

    if(0 == itc)
    {
        goto failed_return;
    }

    memset(itc, 0, sizeof( struct itc_double_queue ));

    itc->daddy2son  = queue_create(bufsize, return_err_buf);
    if(0 == itc->daddy2son)
    {
        goto failed_return;
    }

    itc->son2daddy  = queue_create(bufsize, return_err_buf);
    if(0 == itc->son2daddy)
    {
        goto failed_return;
    }

    return (void*)itc;

failed_return:

    if(itc)
    {
        if(itc->daddy2son)
        {
            queue_destory(itc->daddy2son);
        }
        if(itc->son2daddy)
        {
            queue_destory(itc->son2daddy);
        }
        free(itc);
    }
    else
    {
        if(return_err_buf)
        {
            memcpy(return_err_buf, strerror(errno), strlen(strerror(errno)));
        }
    }

    return 0;
}


#define DADDY_2_SON                 (0)
#define SON_2_DADDY                 (1)
#define WRITE                       (2)
#define READ                        (3)
int
itc_call_queue( const void              *itc,
                const struct itc_msg    *im,
                unsigned char           *return_err_buf,
                unsigned char           way,
                unsigned char           fun)
{
    void                    *q  = 0;
    struct itc_double_queue *it = itc;

    if(0 == itc || 0 == im)
    {
        if(return_err_buf)
        {
            char    *err    = "itc or im is nullpointer!";
            memcpy(return_err_buf, err, strlen(err));
        }
        return false;
    }

    switch(way)
    {
        case DADDY_2_SON:   q = it->daddy2son;     break;
        case SON_2_DADDY:   q = it->son2daddy;     break;
        default:            return false;
    }

    switch(fun)
    {
        case WRITE:
        {
            return queue_write_message(q, im->msg,
                                        im->msg_len, return_err_buf);
        }
        case READ:
        {
            return queue_read_message(q, &(im->msg),
                                        &(im->msg_len), return_err_buf);
        }
        default:
            return false;
    }
}


int
itc_say_to_son( const void              *itc,
                const struct itc_msg    *im,
                unsigned char           *return_err_buf)
{
    return itc_call_queue(itc, im, return_err_buf, DADDY_2_SON, WRITE);
}


int
itc_say_to_daddy(   const void              *itc,
                    const struct itc_msg    *im,
                    unsigned char           *return_err_buf)
{
    return itc_call_queue(itc, im, return_err_buf, SON_2_DADDY, WRITE);
}


int
itc_hear_from_son(  const void              *itc,
                    const struct itc_msg    *im,
                    unsigned char           *return_err_buf)
{
    struct itc_double_queue *it = itc;

    switch(itc_call_queue(it, im, return_err_buf, SON_2_DADDY, READ))
    {
        case QEUUE_NO_MSG:
            return ITC_NO_MSG;
        case QUEUE_ERROR:
            return ITC_ERROR;
        case QUEUE_END:
            it->son2daddy   = queue_destory(it->son2daddy);
            if(0 == it->daddy2son)
            {
                free(it);
                return ITC_DESTORY;
            }
            return ITC_END_MSG;
    }
    return false;
}


int
itc_hear_from_daddy(const void              *itc,
                    const struct itc_msg    *im,
                    unsigned char           *return_err_buf)
{
    struct itc_double_queue *it = itc;

    switch(itc_call_queue(it, im, return_err_buf, DADDY_2_SON, READ))
    {
        case QEUUE_NO_MSG:
            return ITC_NO_MSG;
        case QUEUE_ERROR:
            return ITC_ERROR;
        case QUEUE_END:
            it->daddy2son   = queue_destory(it->daddy2son);
            if(0 == it->son2daddy)
            {
                free(it);
                return ITC_DESTORY;
            }
            return ITC_END_MSG;
    }
    return false;
}


int
itc_kill_my_son(const void *itc)
{
    struct itc_double_queue *it = itc;

    if(it && it->daddy2son)
    {
        queue_write_end(it->daddy2son);
        return true;
    }
    return false;
}


int
itc_kill_my_daddy(const void *itc)
{
    struct itc_double_queue *it = itc;

    if(it && it->son2daddy)
    {
        queue_write_end(it->son2daddy);
        return true;
    }
    return false;
}



























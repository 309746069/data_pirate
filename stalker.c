#include "stalker.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "queue.h"

// stalker control code
struct s_c_c
{
    unsigned int    msg_type;

#define S_SET_WORKER_FUN                1
#define S_UNSET_WORKER_FUN              2
#define S_THREAD_QUIT                   3
#define S_NEW_PACKET                    4
    unsigned int    msg_len;
    unsigned char   msg[1];
};

struct stalker_info
{
    pthread_t           stalker;
    void                *mq;        // message queue
    pthread_mutex_t     mut;
    pthread_cond_t      cond;
#define RUN             1
#define STOP            0
    unsigned int        status;

    unsigned int (*thread_worker)(void *si, void *pi);

    void                *exptr;
};



unsigned int
worker_null(void *si, void *pi)
{
    return false;
}


unsigned int
thread_wakeup(struct stalker_info *si)
{
    if(STOP == si->status)
    {
        pthread_mutex_lock(&(si->mut));
        si->status = RUN;
        pthread_cond_signal(&si->cond);
        pthread_mutex_unlock(&(si->mut));
    }

    return true;
}


unsigned int
thread_sleep(struct stalker_info *si)
{
    if(RUN == si->status)
    {
        pthread_mutex_lock(&(si->mut));
        si->status = STOP;
        // sleep 
        while(STOP == si->status) pthread_cond_wait(&(si->cond), &(si->mut));
        pthread_mutex_unlock(&(si->mut));
    }

    return true;
}



// return true for sleep and wait to be called on next loop
// return false for exit thread
unsigned int
thread_loop(struct stalker_info *si)
{
    struct s_c_c    *cm = 0;
    unsigned int    len = 0;
    unsigned int    ret = 0;

    for(;;)
    {
        cm  = 0;
        ret = queue_read_message(si->mq, &cm, &len, 0);
        // thread exit 
        if(QUEUE_END == ret)
        {
            return false;
        }

        else if(QEUUE_NO_MSG == ret || 0 == cm)
        {
            // return to sleep;
            return true;
        }

        switch(cm->msg_type)
        {
            case S_SET_WORKER_FUN:
                si->thread_worker   = (int(*)(void*))( *((void**)(cm->msg)) );
                break;
            case S_UNSET_WORKER_FUN:
                si->thread_worker   = worker_null;
                break;
            case S_THREAD_QUIT:
                return false;
                break;
            case S_NEW_PACKET:
                if(false == (*(si->thread_worker))(si, *((void**)(cm->msg)) ) )
                    return false;
                break;
            default:
                break;
        }
    }
}



void*
thread_main(struct stalker_info *si)
{
    while( thread_loop(si) && thread_sleep(si) );

    return 0;
}



unsigned int
thread_exit(pthread_t t)
{
    if(!t) return true;
    pthread_cancel(t);
    pthread_join(t, 0);
    return true;
}


void
si_free(struct stalker_info *si)
{
    if(!si) return;

    if(si->stalker)
    {
        thread_exit(si->stalker);
    }

    if(si->mq)
    {
        si->mq  = queue_destory(si->mq);
    }
}


struct stalker_info*
si_malloc(void)
{
    struct stalker_info *si     = 0;
    unsigned int        size    = sizeof(struct stalker_info);

    si  = malloc(size);
    if(0 == si) goto fail_return;
    memset(si, 0, size);

    si->mq  = queue_create(0, 0);
    if(0 == si->mq) goto fail_return;

    si->thread_worker   = worker_null;

    if(0 != pthread_create(&(si->stalker), 0, thread_main, si))
        goto fail_return;

    pthread_mutex_init(&(si->mut), 0);
    pthread_cond_init(&(si->cond), 0);
    si->status  = RUN;

success_return:
    return si;

fail_return:
    si_free(si);
    return 0;
}


void*
stalker_create(void)
{
    struct stalker_info *si     = si_malloc();

    return si;
}


unsigned int
do_push_ptr(struct stalker_info *si, unsigned int msg_type, void *ptr)
{
    if(!si) return false;
    union
    {
        unsigned char   buf[sizeof(struct s_c_c) + 4];
        struct s_c_c    cm;
    }umsg;

    umsg.cm.msg_type    = msg_type;
    umsg.cm.msg_len     = sizeof(ptr);
    memcpy(umsg.cm.msg, &ptr, umsg.cm.msg_len);

    queue_write_message(si->mq, &umsg, sizeof(umsg), 0);

    return true;
}


unsigned int
stalker_set_callback(void *si, unsigned int(*callback)(void*,void*))
{
    return do_push_ptr(si, S_SET_WORKER_FUN, callback) && thread_wakeup(si);
}


unsigned int
stalker_set_callback_null(void *si)
{
    return do_push_ptr(si, S_UNSET_WORKER_FUN, 0) && thread_wakeup(si);
}


unsigned int
stalker_push_new_ptr(void *si, void *ptr)
{
    return do_push_ptr(si, S_NEW_PACKET, ptr) && thread_wakeup(si);
}


unsigned int
stalker_stop(void *si)
{
    return do_push_ptr(si, S_THREAD_QUIT, 0) && thread_wakeup(si);
}


unsigned int
do_wirte_end(struct stalker_info *si)
{
    return si ? queue_write_end(si->mq) : false;
}


unsigned int
stalker_stop_until_no_msg(void *si)
{
    return do_wirte_end(si) && thread_wakeup(si);
}


unsigned int
stalker_set_exptr(void *si, void *ptr)
{
    return si ? ((struct stalker_info*)si)->exptr = ptr : false;
}


void*
stalker_get_exptr(void *si)
{
    return si ? ((struct stalker_info*)si)->exptr : 0;
}

















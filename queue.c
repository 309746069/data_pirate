#include "queue.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "common.h"

#if 0
// only count, cannot show is memory overflow
unsigned int malloc_count   = 0;
unsigned int free_count     = 0;

#define malloc(xxx) malloc(xxx);                                               \
                    printf("============ malloc_count : %u\n", malloc_count ++);
#define free(xxx)   free(xxx);                                                 \
                    printf("============ free_count : %u\n", free_count ++);
#endif


#define _GET_WRITE_MSG_HDR(__queue_)    (                                      \
                    (struct _message_hdr*)( __queue_->widx.offset +            \
                    (unsigned char*)__queue_->widx.current_node->buf ) )

#define _GET_READ_MSG_HDR(__queue_)     (                                      \
                    (struct _message_hdr*)( __queue_->ridx.offset +            \
                    (unsigned char*)__queue_->ridx.current_node->buf ) )


struct list_node
{
    void            *next;
    unsigned char   *buf;
};


struct _message_hdr
{
#define NO_MSG                      0
#define HAVA_MSG                    1
#define NODE_END_MSG                2
#define MESSAGE_QUEUE_END_MSG       3
    unsigned char   state;
    unsigned int    len;
    /* payload */
};


struct message_queue
{
    struct
    {
        struct list_node    *current_node;
        unsigned int        offset;
    }ridx, widx;    // read index, write index

#define _WRITE_NODE(__queue_)       (__queue_->widx.current_node)
#define _READ_NODE(__queue_)        (__queue_->ridx.current_node)

#define _WRITE_OFFSET(__queue_)      (__queue_->widx.offset)
#define _READ_OFFSET(__queue_)       (__queue_->ridx.offset)

    unsigned int        node_buf_size;
    // todo: use this err buf
    unsigned char       err[1024];
};



struct list_node*
node_malloc(struct message_queue *queue)
{
    struct list_node    *node   = 0;

    node    = (struct list_node*)malloc(sizeof(struct list_node));
    if(0 == node)
    {
        return 0;
    }
    memset(node, 0, sizeof(struct list_node));

    node->buf   = (unsigned char*)malloc(queue->node_buf_size);
    if(0 == node->buf)
    {
        free(node);
        return 0;
    }
    memset(node->buf, 0, queue->node_buf_size);

    return node;
}


void
node_free(struct list_node *node)
{
    free(node->buf);
    free(node);
}




void*
queue_init( const unsigned int  per_node_size,
            unsigned char       *return_err)
{
    struct message_queue    *queue  = 0;
    struct _message_hdr     *msghdr = 0;

    // create message_queue
    queue   = (struct message_queue*)malloc(sizeof(struct message_queue));
    if(0 == queue)
    {
        goto failed_return;
    }
    memset(queue, 0, sizeof(struct message_queue));

    queue->node_buf_size    = per_node_size > sizeof(struct _message_hdr)*3 ?
                                 per_node_size : 1024*64;

    // create queue list root
    _WRITE_NODE(queue)  = node_malloc(queue);
    if(0 == _WRITE_NODE(queue))
    {
        goto failed_return;
    }
    _WRITE_NODE(queue)->next    = 0;

    // set index
    _WRITE_OFFSET(queue)    = 0;
    _READ_NODE(queue)       = _WRITE_NODE(queue);
    _READ_OFFSET(queue)     = 0;

    // set first message null
    msghdr          = _GET_WRITE_MSG_HDR(queue);
    msghdr->state   = NO_MSG;
    msghdr->len     = 0;

success_return:

    return (void*)queue;

failed_return:

    if(return_err)
    {
        *return_err = 0;
        memcpy(return_err, strerror(errno), strlen(strerror(errno)));
    }

    if(queue)
    {
        if(_WRITE_NODE(queue))
        {
            free(_WRITE_NODE(queue));
        }
        free(queue);
    }
    return 0;
}






int
queue_write_message(const void          *queue,
                    const unsigned char *msg,
                    const unsigned int  msg_len,
                    unsigned char       *return_err)
{
    struct message_queue    *q          = (struct message_queue*)queue;
    struct _message_hdr     *msghdr     = _GET_WRITE_MSG_HDR(q);
    unsigned int            freesize    = q->node_buf_size - _WRITE_OFFSET(q);

    if(0 == q)
    {
        if(return_err)
        {
            char    *retstring  = "message_queue is empty!\n";
            memcpy(return_err, retstring, strlen(retstring));
        }
        return false;
    }

    // current node freesize not enough  (PS: *2,for NODE_END_MSG)
    if(sizeof(struct _message_hdr)*2 + msg_len >= freesize)
    {
        _WRITE_NODE(q)->next    = node_malloc(q);
        if(0 == _WRITE_NODE(q)->next)
        {
            if(return_err)
            {
                memcpy(return_err, strerror(errno), strlen(strerror(errno)));
            }
            return false;
        }

        _WRITE_NODE(q)          = _WRITE_NODE(q)->next;
        _WRITE_OFFSET(q)        = 0;
        // set no message
        memset(_WRITE_NODE(q), 0, sizeof(struct _message_hdr));

        msghdr->state           = NODE_END_MSG;
        msghdr                  = _GET_WRITE_MSG_HDR(q);
    }

    msghdr->len = msg_len;
    memcpy((unsigned char*)msghdr + sizeof(struct _message_hdr), msg, msg_len);

    // set write offset
    _WRITE_OFFSET(q)    += sizeof(struct _message_hdr) + msg_len;

    msghdr->state   = HAVA_MSG;

    return true;
}


int
queue_get_next_msg_len(void *queue)
{
    struct message_queue    *q          = (struct message_queue*)queue;
    struct _message_hdr     *msghdr     = _GET_READ_MSG_HDR(q);
    struct list_node        *tmp        = _READ_NODE(q);

    if(0 == q)
    {
        return 0;
    }

    switch(msghdr->state)
    {
        case NO_MSG:
            return 0;
        case HAVA_MSG:
            return msghdr->len;
        case NODE_END_MSG:
        {
            _READ_NODE(q)   = _READ_NODE(q)->next;
            _READ_OFFSET(q) = 0;

            node_free(tmp);

            return queue_get_next_msg_len(q);
        }
        case MESSAGE_QUEUE_END_MSG:
            return 0;
        default:
            return 0;
    }
}


int
queue_read_message( void            *queue,
                    unsigned char   *msg_buf)
{
    struct message_queue    *q          = (struct message_queue*)queue;
    struct _message_hdr     *msghdr     = 0;

    if(0 == q)
    {
        return 0;
    }

    if(0 == queue_get_next_msg_len(queue))
    {
        return 0;
    }

    msghdr     = _GET_READ_MSG_HDR(q);

    memcpy( msg_buf,
            (unsigned char*)msghdr + sizeof(struct _message_hdr),
            msghdr->len);

    _READ_OFFSET(q) += sizeof(struct _message_hdr) + msghdr->len;

    return msghdr->len;
}
























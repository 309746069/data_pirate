#pragma once


#define QUEUE_ERROR                     -1
#define QUEUE_NODE_DEFAULT_SIZE         1024*64


void*
queue_new(  const unsigned int  per_node_size,
            unsigned char       *return_err_buf);

int
queue_write_message(const void          *queue,
                    const unsigned char *msg,
                    const unsigned int  msg_len);

int
queue_get_next_msg_len(void *queue);

int
queue_read_message( void            *queue,
                    unsigned char   **ret_msg_ptr);

unsigned char*
queue_last_error(void *queue);
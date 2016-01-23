#pragma once


void*
queue_init( const unsigned int  per_node_size,
            unsigned char       *return_err);

int
queue_write_message(const void          *queue,
                    const unsigned char *msg,
                    const unsigned int  msg_len,
                    unsigned char       *return_err);

int
queue_get_next_msg_len(void *queue);

int
queue_read_message( void            *queue,
                    unsigned char   *msg_buf);
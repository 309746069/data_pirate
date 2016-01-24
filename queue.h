#pragma once

#define QEUUE_NO_MSG                    (0)
#define QUEUE_ERROR                     (-1)
#define QUEUE_END                       (-2)


#define QUEUE_NODE_DEFAULT_SIZE         (1024*64)


void*
queue_create(   const unsigned int  per_node_size,
                unsigned char       *return_err_buf);

// writer thread function ======================================================
int
queue_write_message(const void          *queue,
                    const unsigned char *msg,
                    const unsigned int  msg_len);

int
queue_write_end(const void *queue);

// reader thread function ======================================================
int
queue_get_next_msg_len(void *queue);

int
queue_read_message( void            *queue,
                    unsigned char   **ret_msg_ptr,
                    unsigned int    *msg_len);

unsigned char*
queue_last_error(void *queue);

unsigned char
queue_test_end(void *queue);

void*
queue_destory(void *queue);
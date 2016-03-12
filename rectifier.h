#pragma once

void*
rect_create(void);

unsigned int
rect_insert(void *rt, void *pi);

// void
// fuck____________________(void *rt);
unsigned int
rect_read_data( void                *rt,
                unsigned char       *ret_data_buf,
                unsigned int        buf_size,
                unsigned int        read_start_seq);
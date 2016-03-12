#include "rectifier.h"

#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "packet_info.h"
#include "router.h"



struct tree_node
{
    void                *pi;
    struct tree_node    *left;
    struct tree_node    *right;
};


struct rectifier
{
    struct tree_node    *root;
};


struct tree_node*
tree_node_malloc(void)
{
    unsigned int        size    = sizeof(struct tree_node);
    struct tree_node    *tn     = malloc(size);

    if(!tn) return 0;
    memset(tn, 0, size);
    return tn;
}


void
tree_node_free(struct tree_node *tn)
{
    if(tn)
    {
        free(tn);
    }
}


void*
rect_create(void)
{
    unsigned int        size    = sizeof(struct rectifier);
    struct rectifier    *rt     = malloc(size);

    if(!rt) return 0;
    memset(rt, 0, size);
    return rt;
}


int
seq_compare(unsigned int seq1, unsigned int seq2)
{
    if(seq1 == seq2) return 0;
    else if(seq1 > seq2) return 1;
    else if(seq1 < seq2) return -1;

    return -2;
}


struct tree_node**
find_my_seat_by_seq(struct rectifier *rt, unsigned int seq)
{
    if(!rt) return 0;

    struct tree_node    **ret   = &rt->root;

    while(true)
    {
        if(0 == *ret) return ret;
        if(!get_tcp_hdr((*ret)->pi)) return 0;
        switch(seq_compare(seq, _ntoh32(get_tcp_hdr((*ret)->pi)->seq)))
        {
            case -1:
                ret = &(*ret)->left;
                break;
            case 0:
                return ret;
            case 1:
                ret = &(*ret)->right;
                break;
            default:
                return 0;
        }
    }
}


struct tree_node**
find_my_seat_by_pkt(struct rectifier *rt, void *pi)
{
    if(!rt || !pi) return 0;
    if(!get_tcp_hdr(pi)) return 0;
    return find_my_seat_by_seq(rt, _ntoh32(get_tcp_hdr(pi)->seq));
}



unsigned int
do_rect_insert(struct rectifier *rt, void *pi)
{
    if(!rt || !pi) return false;

    struct tree_node    **seat  = find_my_seat_by_pkt(rt, pi);
    if(!seat) return false;
    if(0 == *seat)
    {
        struct tree_node    *node   = tree_node_malloc();
        node->pi    = pi;
        *seat       = node;
    }
    // already in
    if(*seat) return false;

    return false;
}


int
rect_do_copy_data(  struct tree_node    *node,
                    unsigned char       *ret_buf,
                    unsigned int        *copied_size,
                    unsigned int        buf_size,
                    unsigned int        seq)
{
    unsigned int    len = 0;

    if(!node) return false;
    if(node->left)
    {
        if(!rect_do_copy_data(node->left, ret_buf, copied_size, buf_size, seq))
            return false;
    }

    // lost some packet
    if(_ntoh32(get_tcp_hdr(node->pi)->seq) == seq)
    {
        len = get_tcp_data_len(node->pi);
        if(len + (*copied_size) <= buf_size)
        {
            memcpy(ret_buf + (*copied_size), get_tcp_data_ptr(node->pi), len);
            *copied_size    += len;
        }
        else
            return false;
    }
    else return false;

    if(node->right)
    {
        seq = (len ? seq + len : seq);

        if(!rect_do_copy_data(node->right, ret_buf, copied_size, buf_size, seq))
            return false;
    }

    return true;
}



unsigned int
do_rect_read_data(  struct rectifier    *rt,
                    unsigned char       *ret_data_buf,
                    unsigned int        buf_size,
                    unsigned int        read_start_seq)
{
    if(!rt || !ret_data_buf ||!buf_size) return 0;

    unsigned int        read_size   = 0;
    struct tree_node    **node      = 0;

    node    = find_my_seat_by_seq(rt, read_start_seq);
    if(0 == node || 0 == *node) return 0;

    rect_do_copy_data(*node, ret_data_buf, &read_size,
                        buf_size, read_start_seq);

    return read_size;
}


unsigned int
rect_read_data( void                *rt,
                unsigned char       *ret_data_buf,
                unsigned int        buf_size,
                unsigned int        read_start_seq)
{
    return do_rect_read_data(rt, ret_data_buf, buf_size, read_start_seq);
}


unsigned int
rect_insert(void *rt, void *pi)
{
    return do_rect_insert(rt, pi);
}

// static unsigned char   out[180000]   = {0};

// void
// out_message(unsigned char *ptr, unsigned int len)
// {
//     if(!ptr) return;
//     memset(out, 0, 180000);
//     memcpy(out, ptr, len);
//     _MESSAGE_OUT("%s", out);
// }


// void
// do_log_out_test(struct tree_node *node)
// {
//     if(!node) return;
//     if(node->left)
//     {
//         do_log_out_test(node->left);
//     }
//     if(get_tcp_data_len(node->pi))
//     {
//         out_message(get_tcp_data_ptr(node->pi), get_tcp_data_len(node->pi));
//     }
//     if(node->right)
//     {
//         do_log_out_test(node->right);
//     }
// }


// void
// log_out_test(struct rectifier *rt)
// {
//     if(!rt) return;

//     do_log_out_test(rt->root);
// }


// void
// fuck____________________(void *rt)
// {
//     log_out_test(rt);
// }

























































// inter thread communication
#pragma once


#define ITC_NO_MSG              (-1)
#define ITC_ERROR               (-2)
// half close
#define ITC_END_MSG             (-3)
// all close, free itc
#define ITC_DESTORY             (-4)

struct itc_msg
{
    unsigned int    msg_len;
    unsigned char   *msg;
};



void*
itc_create(const unsigned int bufsize, unsigned char *return_err_buf);

int
itc_say_to_son( const void              *itc,
                const struct itc_msg    *im,
                unsigned char           *return_err_buf);

int
itc_say_to_daddy(   const void              *itc,
                    const struct itc_msg    *im,
                    unsigned char           *return_err_buf);

int
itc_hear_from_son(  const void              *itc,
                    const struct itc_msg    *im,
                    unsigned char           *return_err_buf);

int
itc_hear_from_daddy(const void              *itc,
                    const struct itc_msg    *im,
                    unsigned char           *return_err_buf);

int
itc_kill_my_son(const void *itc);

int
itc_kill_my_daddy(const void *itc);
#pragma once


// build option ================================================================
#define ___MESSAGE_LOG__
#define ___DEBUG__
#define ___LOG_CLEAN__
#define __LITTLE_ENDIAN_BITFIELD

#ifndef ___MODULE_NAME
    #define ___MODULE_NAME              "data_pirate"
#endif
#if !defined(__LITTLE_ENDIAN_BITFIELD) && !defined(__BIG_ENDIAN_BITFIELD)
    #define __LITTLE_ENDIAN_BITFIELD
    #warning "use default definition __LITTLE_ENDIAN_BITFIELD"
#endif


// common define ===============================================================
#ifndef TRUE
    #define TRUE                        (1)
#endif
#ifndef FALSE
    #define FALSE                       (0)
#endif
#ifndef true
    #define true                        (1)
#endif
#ifndef false
    #define false                       (0)
#endif

// function pointer ============================================================
int __log_out_null(char*, ...);
int __send_package_null(const unsigned char*, const unsigned int);

typedef int (*LOG_OUT_FUN)(char*, ...);
typedef int (*SEND_PACKAGE_FUN)(const unsigned char*, const unsigned int);

extern LOG_OUT_FUN          _log_out;
extern SEND_PACKAGE_FUN     _send_package;

// void duff_memclr(char*, unsigned int);
// void duff_memcpy(char*, char*, unsigned int);
unsigned int
_ntoh32(unsigned int);

unsigned short
_ntoh16(unsigned short);

unsigned int
_iptonetint32(char*);

unsigned char*
_netint32toip(unsigned int);

int
net_state_init( const unsigned char*,
                const unsigned char*,
                const unsigned int,
                const unsigned int,
                const unsigned int);



// function define =============================================================
#define _SET_LOG_OUT_FUN(__fun_)        _log_out      = (LOG_OUT_FUN)__fun_
#define _SET_SEND_PACKAGE_FUN(__fun_)   _send_package = (SEND_PACKAGE_FUN)__fun_

#define _SEND_PACKAGE(__pkt_, __pkt_size_)                                     \
    (*_send_package)((unsigned char*)__pkt_, (unsigned int)__pkt_size_)

// message log define
#if defined(___MESSAGE_LOG__) && defined(___LOG_CLEAN__)
    #define _MESSAGE_OUT(format, args...)                                      \
                    (*_log_out)(format,##args)
#elif defined(___MESSAGE_LOG__) && !defined(___LOG_CLEAN__)
    #define _MESSAGE_OUT(format, args...)                                      \
                    (*_log_out)(___MODULE_NAME":\t"format,##args)
#else
    #define _MESSAGE_OUT(format, args...)
#endif
// debug log define
#ifdef ___DEBUG__
    #define _DEBUG_LOG(format, args...)                                        \
                    _MESSAGE_OUT(format, ##args)
#else
    #define _DEBUG_LOG(format, args...)
#endif











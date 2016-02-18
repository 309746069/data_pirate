#pragma once

#ifndef GZIP_H
    #define GZIP_H
#endif

#include <zlib.h>



int gzcompress(Bytef *data, uLong ndata,
               Bytef *zdata, uLong *nzdata);

int gzdecompress(Byte *zdata, uLong nzdata,
                 Byte *data, uLong *ndata);
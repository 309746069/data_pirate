#pragma once


void*
tr_init_c2s(void *pi);

void
tr_destory(void *tr);

unsigned int
tr_receive(void *tr, void *pi);

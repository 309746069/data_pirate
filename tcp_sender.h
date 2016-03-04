#pragma once



void*
tr_create(void);

void
tr_destory(void *tr);

unsigned int
tr_receive(void *tr, void *pi);
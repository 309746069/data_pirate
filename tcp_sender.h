#pragma once


void*
tr_create_mitm(void *pi);

unsigned int
tr_receive_mitm(void *trp, void *pi);

void
tr_destory_mitm(void *trp);

void
tr_test(void *pi);
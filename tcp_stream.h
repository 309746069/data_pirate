#pragma once



void*
tss_create(void);

unsigned int
tss_insert(void *tss, void *pi);

unsigned int
tss_search(void *tss, void *pi);

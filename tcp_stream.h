#pragma once



void*
tss_create(void);

unsigned int
tss_insert(void *tss, void *pi);

unsigned int
tss_search(void *tss, void *pi);

unsigned int
tss_add_s2c_data_size(void *tss, void *pi, unsigned int add_data_size);

unsigned int
tss_s2c_data_size(void *tss, void *pi);

unsigned int
tss_s2c_insert_start_seq(void *tss, void *pi);
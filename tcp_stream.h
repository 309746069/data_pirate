#pragma once



void*
tss_create(void);

unsigned int
tss_c2s_insert(void *tss, void *pi);

unsigned int
tss_s2c_insert(void *tss, void *pi);

unsigned int
tss_search(void *tss, void *pi);

unsigned int
tss_s2c_insert_data_size(void *tss, void *pi, int insert_data_size);

int
tss_s2c_data_size(void *tss, void *pi);

unsigned int
tss_s2c_insert_start_seq(void *tss, void *pi);

unsigned int
tss_c2s_insert_data_size(void *tss, void *pi, int insert_data_size);

int
tss_c2s_data_size(void *tss, void *pi);

unsigned int
tss_c2s_insert_start_seq(void *tss, void *pi);

unsigned int
tss_is_client_to_server(void *tss, void *pi);

unsigned int
tss_set_stalker(void *tss, void *pi, void *stalker);

void*
tss_get_stalker(void *tss, void *pi);

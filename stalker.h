#pragma once

// thread factory

void*
stalker_create(void);

unsigned int
stalker_set_callback(void *si, unsigned int(*callback)(void*,void*));

unsigned int
stalker_set_callback_null(void *si);

unsigned int
stalker_push_new_ptr(void *si, void *ptr);

unsigned int
stalker_stop(void *si);

unsigned int
stalker_stop_until_no_msg(void *si);


// worker thread ===============================================================
unsigned int
stalker_set_exptr(void *si, void *ptr);

void*
stalker_get_exptr(void *si);
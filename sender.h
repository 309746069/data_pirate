#pragma once


int
sender_initialize(const char* interface, char** return_err);

int
sender_send(const unsigned char* packet, const unsigned int size);

void
sender_finish(void);

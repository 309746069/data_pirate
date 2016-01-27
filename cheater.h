#pragma once

void
cheater_test(void);

// control cheater thread ======================================================
int
cheater_start(void);

void
cheater_stop(void);

// mode = 1 cheat on target, mode = 0 mitm in target with route
int
cheater_add(unsigned int ip_netint32, unsigned char mode);
// cheater_add wrapper
int
cheater_add_mitm(unsigned int ip_netint32);

int
cheater_delete(unsigned int ip_netint32);

// run in caller thread ========================================================
void
cheater_scan(void);
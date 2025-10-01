#ifndef UDP_H
#define UDP_H

#include <openthread/instance.h>

void send_udp_to_all_seds(otInstance *instance);

void udp_listener_start(otInstance *instance);

#endif 

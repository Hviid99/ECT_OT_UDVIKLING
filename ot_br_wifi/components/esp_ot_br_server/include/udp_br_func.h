#pragma once

#include <openthread/instance.h>
#include <openthread/link.h>  
#include "esp_err.h"
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool valid;
    int voltage;
    char status[32];
    char mleid[64];
    char extaddr[32];
    uint16_t rloc16;
    time_t last_seen;
    char last_seen_str[32];
} sed_status_t;

#define MAX_SEDS 10

void send_udp_to_all_seds(otInstance *instance);

void udp_listener_start(otInstance *instance);

const char *udp_get_last_status(void);

const char *udp_get_all_status(char *buf, size_t bufsize);

const sed_status_t *udp_get_status(int idx);

void update_sed_thread_info(sed_status_t *sed, otInstance *instance);


#ifdef __cplusplus
}
#endif

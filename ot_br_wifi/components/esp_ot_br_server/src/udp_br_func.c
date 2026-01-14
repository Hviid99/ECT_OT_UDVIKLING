#include "udp_br_func.h"
#include "esp_log.h"
#include "esp_openthread.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include <openthread/thread.h>
#include <openthread/thread_ftd.h>
#include <openthread/ip6.h>
#include "cJSON.h"
#include <time.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>


#define UDP_PORT_SEND   12345   // hvor vi sender BREQ
#define UDP_PAYLOAD     "BREQ"

#define UDP_PORT_LISTEN 54321   // samme port som devices svarer på

#define TAG "UDP_BR"
#define MAX_SEDS 10
static sed_status_t sed_status[MAX_SEDS];   // global status for SEDs
void update_sed_thread_info(sed_status_t *sed, otInstance *instance);
static uint16_t find_sed_by_address(struct sockaddr_in6 *source_addr);

// -----------------------------------------------------------
// Hjælp: find ledig eller eksisterende SED-slot ud fra RLOC16
// -----------------------------------------------------------
static int find_sed_slot(uint16_t rloc16)
{
    for (int i = 0; i < MAX_SEDS; i++) {
        if (sed_status[i].valid && sed_status[i].rloc16 == rloc16) {
            return i; // eksisterende
        }
    }
    for (int i = 0; i < MAX_SEDS; i++) {
        if (!sed_status[i].valid) {
            sed_status[i].rloc16 = rloc16;
            sed_status[i].valid = true;
            return i; // nyt slot
        }
    }
    return -1; // ingen plads
}

// -----------------------------------------------------------
// Send UDP til alle børn (kun SEDs)
// -----------------------------------------------------------
void send_udp_to_all_seds_with_payload(otInstance *instance, const char *payload, const char *log_tag)
{
    if (!instance) {
        ESP_LOGE(TAG, "No OpenThread instance available");
        return;
    }

    if (!payload) {
        ESP_LOGE(TAG, "No payload provided");
        return;
    }

    int sock_tx = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock_tx < 0) {
        ESP_LOGE(TAG, "TX socket create failed (errno=%d)", errno);
        return;
    }

    uint16_t max_children = otThreadGetMaxAllowedChildren(instance);

    for (uint16_t i = 0; i < max_children; i++) {
        otChildInfo child;
        if (otThreadGetChildInfoByIndex(instance, i, &child) != OT_ERROR_NONE) {
            continue;
        }

        if (!child.mFullThreadDevice) { // Kun SED
            otChildIp6AddressIterator iter = OT_CHILD_IP6_ADDRESS_ITERATOR_INIT;
            otIp6Address ip;
            otError err;

            do {
                err = otThreadGetChildNextIp6Address(instance, i, &iter, &ip);
                if (err == OT_ERROR_NONE) {
                    struct sockaddr_in6 dest = {0};
                    dest.sin6_family = AF_INET6;
                    dest.sin6_port   = htons(UDP_PORT_SEND);
                    memcpy(&dest.sin6_addr, &ip, sizeof(ip));

                    int ret = sendto(sock_tx, payload, strlen(payload), 0,
                                     (struct sockaddr *)&dest, sizeof(dest));
                    if (ret < 0) {
                        ESP_LOGE(TAG, "UDP send error (errno=%d)", errno);
                    } else {
                        ESP_LOGI(TAG, "%s sent to child RLOC16=0x%04x", 
                                log_tag ? log_tag : "Message", child.mRloc16);
                    }
                }
            } while (err == OT_ERROR_NONE);
        }
    }

    close(sock_tx);
}

// -----------------------------------------------------------
// UDP listener task
// -----------------------------------------------------------
static void udp_listener_task(void *arg)
{
    int sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Listener socket create failed: errno=%d", errno);
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in6 addr = {0};
    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(UDP_PORT_LISTEN);
    addr.sin6_addr   = in6addr_any;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "Bind failed: errno=%d", errno);
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "UDP listener started on port %d", UDP_PORT_LISTEN);

    while (1) {
        char rx_buffer[256];
        struct sockaddr_in6 source_addr;
        socklen_t socklen = sizeof(source_addr);

        int len = recvfrom(sock, rx_buffer, sizeof(rx_buffer) - 1, 0,
                           (struct sockaddr *)&source_addr, &socklen);

        if (len > 0) {
            rx_buffer[len] = 0; // nul-terminer
            ESP_LOGI(TAG, "UDP received: %s", rx_buffer);

            // Check if it's a command message (non-JSON)
            if (strncmp(rx_buffer, "fire", 4) == 0) {
                ESP_LOGI(TAG, "Fire command received from SED!");
    
                // Find which SED sent this message by comparing source address
                uint16_t sender_rloc16 = find_sed_by_address(&source_addr);
    
            if (sender_rloc16 != 0) {
             // Update only the SED that sent the fire message
                for (int i = 0; i < MAX_SEDS; i++) {
                    if (sed_status[i].valid && sed_status[i].rloc16 == sender_rloc16) {
                        sed_status[i].fire_detected = true;
                        strncpy(sed_status[i].status, "FIRE", sizeof(sed_status[i].status) - 1);
                        ESP_LOGI(TAG, "SED with RLOC16 0x%04x marked as FIRE DETECTED", sender_rloc16);
                        break;
                    }
                }
                otInstance *instance = esp_openthread_get_instance();
                if (instance) {
                    send_udp_to_all_seds_with_payload(instance, "ALARM_START", "Fire alarm broadcast");
                    ESP_LOGI(TAG, "Broadcasted FALARM to all SEDs");
                }    
            } else {
                ESP_LOGW(TAG, "Could not identify which SED sent fire message");
            }
    
            continue; // Skip JSON parsing for command messages
        }
            
        else if (strncmp(rx_buffer, "HUSH_ACK", 8) == 0) {
            ESP_LOGI(TAG, "=== HUSH_ACK RECEIVED ===");
            ESP_LOGI(TAG, "Raw message: %s", rx_buffer);
            
            // Find which SED sent this message by comparing source address
            uint16_t sender_rloc16 = find_sed_by_address(&source_addr);
            
            if (sender_rloc16 != 0) {
                ESP_LOGI(TAG, "HUSH_ACK from SED with RLOC16: 0x%04x", sender_rloc16);
                
                // Find the SED index by RLOC16 and update its fire state
                for (int i = 0; i < MAX_SEDS; i++) {
                    if (sed_status[i].valid && sed_status[i].rloc16 == sender_rloc16) {
                        ESP_LOGI(TAG, "Found matching SED at index %d", i);
                        
                        // Update fire state for this SED
                        bool old_state = sed_status[i].fire_detected;
                        sed_status[i].fire_detected = false;
                        strncpy(sed_status[i].status, "NORMAL", sizeof(sed_status[i].status) - 1);
                        
                        ESP_LOGI(TAG, "SUCCESS: SED%d (RLOC16 0x%04x) fire state updated: %d -> %d", 
                                i+1, sender_rloc16, old_state, false);
                        break;
                    }
                }
            } else {
                ESP_LOGW(TAG, "Could not identify which SED sent HUSH_ACK");
            }
            
            ESP_LOGI(TAG, "=== HUSH_ACK PROCESSING COMPLETE ===");
            continue;
        }

        else if (strncmp(rx_buffer, "ALARM_ONLY", 10) == 0) {
            ESP_LOGI(TAG, "Alarm only (no fire) command received from SED!");
            
            // Find which SED sent this message by comparing source address
            uint16_t sender_rloc16 = find_sed_by_address(&source_addr);
            
            if (sender_rloc16 != 0) {
                // Update only the SED that sent the alarm_only message
                for (int i = 0; i < MAX_SEDS; i++) {
                    if (sed_status[i].valid && sed_status[i].rloc16 == sender_rloc16) {
                        sed_status[i].fire_detected = false; // Not actual fire
                        strncpy(sed_status[i].status, "ALARM", sizeof(sed_status[i].status) - 1);
                        ESP_LOGI(TAG, "SED with RLOC16 0x%04x marked as ALARM ONLY", sender_rloc16);
                        break;
                    }
                }
            } else {
                ESP_LOGW(TAG, "Could not identify which SED sent ALARM_ONLY message");
            }
            
            continue; // Skip JSON parsing for command messages
        }

            // Parse JSON med cJSON (existing battery status functionality)
            cJSON *root = cJSON_Parse(rx_buffer);
            if (root) {
                int voltage = cJSON_GetObjectItem(root, "voltage")->valueint;
                const char *status  = cJSON_GetObjectItem(root, "status")->valuestring;
                const char *mleid   = cJSON_GetObjectItem(root, "mleid")->valuestring;
                const char *rloc16s = cJSON_GetObjectItem(root, "rloc16")->valuestring;
                const char *extaddr = cJSON_GetObjectItem(root, "extaddr")->valuestring;

                uint16_t rloc16 = (uint16_t)strtol(rloc16s, NULL, 0);

                int idx = find_sed_slot(rloc16);
                if (idx >= 0) {
                    sed_status[idx].voltage = voltage;
                    strncpy(sed_status[idx].status, status,
                            sizeof(sed_status[idx].status) - 1);
                    strncpy(sed_status[idx].mleid, mleid,
                            sizeof(sed_status[idx].mleid) - 1);
                    strncpy(sed_status[idx].extaddr, extaddr,
                            sizeof(sed_status[idx].extaddr) - 1);
                    sed_status[idx].rloc16 = rloc16;

                    // Sæt last_seen til nuværende tid
                    sed_status[idx].last_seen = time(NULL);

                    ESP_LOGI(TAG,
                             "Updated SED%d: %d mV, %s, MLEID=%s, RLOC16=0x%04x, ExtAddr=%s, LastSeen=%ld",
                             idx + 1,
                             voltage,
                             sed_status[idx].status,
                             sed_status[idx].mleid,
                             sed_status[idx].rloc16,
                             sed_status[idx].extaddr,
                             sed_status[idx].last_seen);
                }

                cJSON_Delete(root);
            } else {
                ESP_LOGW(TAG, "Invalid JSON from SED: %s", rx_buffer);
            }
        }
    }

    close(sock);
    vTaskDelete(NULL);
}



// -----------------------------------------------------------
// Start listener fra main/init
// -----------------------------------------------------------
void udp_listener_start(otInstance *instance)
{
    (void)instance; // ikke brugt lige nu
    xTaskCreate(udp_listener_task, "udp_listener", 4096, NULL, 5, NULL);
}

// -----------------------------------------------------------
// Getter til web: returnér pointer + antal
// -----------------------------------------------------------
const char *udp_get_all_status(char *buf, size_t bufsize)
{
    cJSON *root = cJSON_CreateObject();

    for (int i = 0; i < MAX_SEDS; i++) {
        if (sed_status[i].rloc16 != 0) {
            cJSON *entry = cJSON_CreateObject();
            cJSON_AddNumberToObject(entry, "voltage", sed_status[i].voltage);
            cJSON_AddStringToObject(entry, "status", sed_status[i].status);
            cJSON_AddStringToObject(entry, "mleid", sed_status[i].mleid);
            cJSON_AddStringToObject(entry, "extaddr", sed_status[i].extaddr);
            
            // ADD THIS: Include fire detection status
            cJSON_AddBoolToObject(entry, "fire_detected", sed_status[i].fire_detected);

            char rloc16_str[16];
            snprintf(rloc16_str, sizeof(rloc16_str), "0x%04x", sed_status[i].rloc16);
            cJSON_AddStringToObject(entry, "rloc16", rloc16_str);

            cJSON_AddNumberToObject(entry, "last_seen", (long)sed_status[i].last_seen);

            char sed_id[8];
            snprintf(sed_id, sizeof(sed_id), "SED%d", i + 1);
            cJSON_AddItemToObject(root, sed_id, entry);
        }
    }

    if (!cJSON_PrintPreallocated(root, buf, bufsize, 0)) {
        ESP_LOGW("UDP_BR", "Buffer too small for JSON status");
        buf[0] = '\0';
    }

    cJSON_Delete(root);
    return buf;
}



const sed_status_t *udp_get_status(int idx)
{
    if (idx < 0 || idx >= MAX_SEDS || !sed_status[idx].valid) {
        return NULL;
    }
    return &sed_status[idx];
}

void update_sed_thread_info(sed_status_t *sed, otInstance *instance)
{
    otChildInfo childInfo;
    uint16_t maxChildren = otThreadGetMaxAllowedChildren(instance);

    for (uint16_t i = 0; i < maxChildren; i++) {
        if (otThreadGetChildInfoByIndex(instance, i, &childInfo) == OT_ERROR_NONE) {
            if (childInfo.mRloc16 == sed->rloc16) {

                otChildIp6AddressIterator iter = OT_CHILD_IP6_ADDRESS_ITERATOR_INIT;
                otIp6Address ip;
                bool found = false;

                while (otThreadGetChildNextIp6Address(instance, i, &iter, &ip) == OT_ERROR_NONE) {
                    // Mesh-local EID starter altid med "fd"
                    if ((ip.mFields.m8[0] & 0xFE) == 0xFC) {
                        otIp6AddressToString(&ip, sed->mleid, sizeof(sed->mleid));
                        ESP_LOGI("SED", "Found MLEID for child 0x%04x -> %s",
                                 sed->rloc16, sed->mleid);
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    strncpy(sed->mleid, "-", sizeof(sed->mleid));
                    sed->mleid[sizeof(sed->mleid) - 1] = '\0';
                    ESP_LOGW("SED", "No MLEID found for child 0x%04x", sed->rloc16);
                }

                return; // færdig for dette barn
            }
        }
    }

    // Hvis vi ikke fandt barnet overhovedet
    strncpy(sed->mleid, "-", sizeof(sed->mleid));
    sed->mleid[sizeof(sed->mleid) - 1] = '\0';
    ESP_LOGW("SED", "Child 0x%04x not found in child table", sed->rloc16);
}


// Helper function to find SED RLOC16 from source address
static uint16_t find_sed_by_address(struct sockaddr_in6 *source_addr)
{
    otInstance *instance = esp_openthread_get_instance();
    if (!instance) {
        return 0;
    }

    // Convert source address to otIp6Address
    otIp6Address src_ip;
    memcpy(&src_ip, &source_addr->sin6_addr, sizeof(otIp6Address));

    // Search through all children to find which one has this IP
    uint16_t max_children = otThreadGetMaxAllowedChildren(instance);
    
    for (uint16_t i = 0; i < max_children; i++) {
        otChildInfo child;
        if (otThreadGetChildInfoByIndex(instance, i, &child) != OT_ERROR_NONE) {
            continue;
        }

        // Check if this child has the source IP
        otChildIp6AddressIterator iter = OT_CHILD_IP6_ADDRESS_ITERATOR_INIT;
        otIp6Address child_ip;
        
        while (otThreadGetChildNextIp6Address(instance, i, &iter, &child_ip) == OT_ERROR_NONE) {
            if (memcmp(&child_ip, &src_ip, sizeof(otIp6Address)) == 0) {
                ESP_LOGI(TAG, "Found matching SED: RLOC16=0x%04x", child.mRloc16);
                return child.mRloc16;
            }
        }
    }
    
    ESP_LOGW(TAG, "No SED found with the source IP address");
    return 0;
}

void update_sed_fire_state(const char *sed_name, bool fire_state) {
    ESP_LOGI(TAG, "=== UPDATE_SED_FIRE_STATE CALLED ===");
    ESP_LOGI(TAG, "Input: sed_name='%s', fire_state=%d", sed_name, fire_state);
    
    // Extract SED number from name (e.g., "SED1" -> 1, "SED2" -> 2)
    int sed_number;
    if (sscanf(sed_name, "SED%d", &sed_number) == 1) {
        ESP_LOGI(TAG, "Parsed SED number: %d", sed_number);
        
        // Convert to array index (SED1 -> index 0, SED2 -> index 1, etc.)
        int idx = sed_number - 1;
        ESP_LOGI(TAG, "Target index: %d", idx);
        
        if (idx >= 0 && idx < MAX_SEDS) {
            if (sed_status[idx].valid) {
                bool old_state = sed_status[idx].fire_detected;
                sed_status[idx].fire_detected = fire_state;
                
                // Update status text based on fire state
                if (fire_state) {
                    strncpy(sed_status[idx].status, "FIRE", sizeof(sed_status[idx].status) - 1);
                } else {
                    strncpy(sed_status[idx].status, "NORMAL", sizeof(sed_status[idx].status) - 1);
                }
                
                ESP_LOGI(TAG, "SUCCESS: SED%d fire state updated: %d -> %d", 
                        sed_number, old_state, fire_state);
                ESP_LOGI(TAG, "SED%d status: %s", sed_number, sed_status[idx].status);
            } else {
                ESP_LOGW(TAG, "SED index %d exists but is not valid", idx);
            }
        } else {
            ESP_LOGW(TAG, "Invalid SED index %d for %s (must be 0-%d)", 
                    idx, sed_name, MAX_SEDS-1);
        }
    } else {
        ESP_LOGW(TAG, "Could not parse SED name: '%s'", sed_name);
        ESP_LOGW(TAG, "Expected format: 'SED1', 'SED2', etc.");
    }
    ESP_LOGI(TAG, "=== UPDATE_SED_FIRE_STATE COMPLETE ===");
}

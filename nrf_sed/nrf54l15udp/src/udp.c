#include "udp.h"
#include "adc.h"
#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "fire.h"

#include "alarm_test.h"
#include <zephyr/sys/printk.h>
#include <openthread/message.h>
#include <openthread/udp.h>

#include <openthread/thread.h>
#include <openthread/link.h>
#include <openthread/ip6.h>

#define LISTEN_PORT   12345
#define RESPONSE_PORT 54321

/* Gem instancen i en global statisk pointer */
static otInstance *g_instance = NULL;

static void udp_server_thread(void)
{
    
    int sock;
    struct sockaddr_in6 addr6;
    char buf[128];

    sock = zsock_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        printk("UDP socket create error: %d\n", errno);
        return;
    }

    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port   = htons(LISTEN_PORT);
    addr6.sin6_addr   = in6addr_any;

    if (zsock_bind(sock, (struct sockaddr *)&addr6, sizeof(addr6)) < 0) {
        printk("UDP bind error: %d\n", errno);
        zsock_close(sock);
        return;
    }

    printk("UDP listener started on port %d\n", LISTEN_PORT);

    while (1) {
        struct sockaddr_in6 src_addr;
        socklen_t addr_len = sizeof(src_addr);

        int len = zsock_recvfrom(sock, buf, sizeof(buf) - 1, 0,
                                 (struct sockaddr *)&src_addr, &addr_len);
        if (len < 0) {
            printk("UDP recv error: %d\n", errno);
            continue;
        }

        buf[len] = '\0';
        printk("UDP received: %s\n", buf);


        // --- ALARM flow ---
        if (strcmp(buf, "ALARMTEST") == 0) {
            alarm_test_trigger();
            continue;
        }

        // --- ALERT_FIRE flow ---
        if (strcmp(buf, "ALARM_START") == 0) {

            if (fire_is_active()) {
                printk("Already active fire alarm – ignoring broadcast\n");
                continue;
            }

            printk("Received ALERT_FIRE broadcast – activating local siren\n");
            fire_start();  // starter blink, men uden at sende 'fire' besked

            // Send 'ALARM_ONLY' svar tilbage til Border Router
            const char *resp_msg = "ALARM_ONLY";
            src_addr.sin6_port = htons(RESPONSE_PORT);   // port 54321
            int ret = zsock_sendto(sock, resp_msg, strlen(resp_msg), 0,
                           (struct sockaddr *)&src_addr, addr_len);

            if (ret < 0)
                printk("UDP send ALARM_ONLY error: %d\n", errno);
            else
                printk("Sent ALARM_ONLY to Border Router\n");

            continue;
        }

        
        // --- HUSH flow ---
        if (strcmp(buf, "HUSH") == 0) {
            fire_stop();   // Kalder din funktion fra fire.c
            printk("UDP received HUSH – stopping fire alarm\n");    
            
            // send bekræftelse tilbage til Border Router
            const char *resp_msg = "HUSH_ACK";
            src_addr.sin6_port = htons(RESPONSE_PORT);   // port 54321
            int ret = zsock_sendto(sock, resp_msg, strlen(resp_msg), 0,
                           (struct sockaddr *)&src_addr, addr_len);
            if (ret < 0) {
                printk("UDP send HUSH_ACK error: %d\n", errno);
            } else {
                printk("Sent HUSH_ACK to Border Router\n");
            }

            continue;
        }


        // --- BREQ flow ---
        if (strstr(buf, "BREQ")) {
            int voltage = get_battery_voltage_mv();
            battery_status_t bat_status = get_battery_status();

            const char *status_str =
                bat_status == BAT_GREEN  ? "GREEN" :
                bat_status == BAT_YELLOW ? "YELLOW" :
                bat_status == BAT_RED    ? "RED" :
                                           "NO BATTERY";

            char mleIdStr[OT_IP6_ADDRESS_STRING_SIZE] = "<none>";
            char extAddrStr[32] = "<none>";
            uint16_t rloc16 = 0xffff;

            if (g_instance) {
                const otIp6Address *mleid = otThreadGetMeshLocalEid(g_instance);
                if (mleid) {
                    otIp6AddressToString(mleid, mleIdStr, sizeof(mleIdStr));
                }

                rloc16 = otThreadGetRloc16(g_instance);

                otExtAddress extAddr;
                otLinkGetFactoryAssignedIeeeEui64(g_instance, &extAddr);
                snprintf(extAddrStr, sizeof(extAddrStr),
                         "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
                         extAddr.m8[0], extAddr.m8[1], extAddr.m8[2], extAddr.m8[3],
                         extAddr.m8[4], extAddr.m8[5], extAddr.m8[6], extAddr.m8[7]);
            }

            char resp[256];
            snprintf(resp, sizeof(resp),
                     "{ \"voltage\": %d, \"status\": \"%s\", "
                     "\"mleid\": \"%s\", \"rloc16\": \"0x%04x\", "
                     "\"extaddr\": \"%s\" }",
                     voltage, status_str,
                     mleIdStr, rloc16,
                     extAddrStr);

            src_addr.sin6_port = htons(RESPONSE_PORT);
            int ret = zsock_sendto(sock, resp, strlen(resp), 0,
                                   (struct sockaddr *)&src_addr, addr_len);
            if (ret < 0) {
                printk("UDP send response error: %d\n", errno);
            } else {
                printk("Sent response: %s\n", resp);
            }
        }
    }

    zsock_close(sock);
}

void udp_listener_start(otInstance *instance)
{
    g_instance = instance;   /* gem instancen til brug i tråden */

    static K_THREAD_STACK_DEFINE(stack_area, 2048);
    static struct k_thread thread_data;

    k_thread_create(&thread_data,
                    stack_area, K_THREAD_STACK_SIZEOF(stack_area),
                    (k_thread_entry_t)udp_server_thread,
                    NULL, NULL, NULL,
                    7, 0, K_NO_WAIT);
}

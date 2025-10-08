#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/printk.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include "fire.h"

// Border Router IPv6-adresse og port
// HUSK at ændre Border Router's adresse
#define BR_IP6 "fd94:59b5:b7ee:779a:6274:9eaa:9cdd:8073"
//#define BR_IP6 "fd78:ee93:e283:a41:ddd7:96ac:ec48:1884"
#define BR_PORT 54321
#define TAG "FIRE"

// --- Hardware konfiguration ---
#define BUTTON_NODE DT_ALIAS(sw0)
#define LED_NODE DT_ALIAS(led0)


static const struct gpio_dt_spec fire_button = GPIO_DT_SPEC_GET(BUTTON_NODE, gpios);
static const struct gpio_dt_spec fire_led = GPIO_DT_SPEC_GET(LED_NODE, gpios);
static struct gpio_callback fire_button_cb;

// --- Global state ---
static otInstance *g_instance = NULL;
static volatile bool fire_active = false;
static struct k_thread fire_thread_data;
K_THREAD_STACK_DEFINE(fire_stack_area, 512);


// --- LED blink ---
void fire_thread(void *a, void *b, void *c)
{
    while (1) {
        if (fire_active) {
            gpio_pin_set_dt(&fire_led, 1);
            k_msleep(300);
            gpio_pin_set_dt(&fire_led, 0);
            k_msleep(300);
        } else {
            k_msleep(100);
        }
    }
}

// --- Start og stop funktioner ---
void fire_start(void)
{
    if (!fire_active) {
        fire_active = true;
        printk("[%s] Fire alarm activated\n", TAG);
    }
}

void fire_stop(void)
{
    fire_active = false;
    gpio_pin_set_dt(&fire_led, 0);
    printk("[%s] Fire alarm stopped (HUSH received)\n", TAG);
}

// --- Knaphåndtering ---
static void fire_button_pressed(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
    printk("[%s] Button pressed sending FIRE!\n", TAG);

    // Start blink lokalt
    fire_start();

    // Send FIRE-besked til Border Router
    int sock = zsock_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        printk("[%s] Socket create failed: %d\n", TAG, errno);
        return;
    }

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(BR_PORT);
    inet_pton(AF_INET6, BR_IP6, &dest.sin6_addr);

    const char *msg = "fire";
    int ret = zsock_sendto(sock, msg, strlen(msg), 0,
                           (struct sockaddr *)&dest, sizeof(dest));
    if (ret < 0)
        printk("[%s] UDP send error: %d\n", TAG, errno);
    else
        printk("[%s] UDP sent: %s\n", TAG, msg);

    zsock_close(sock);
}

// --- Init ---
void fire_init(otInstance *instance)
void fire_init(void)

{
    // - mulig redundans: g_instance = instance;

    if (!device_is_ready(fire_button.port)) {
        printk("[%s] Button device not ready\n", TAG);
        return;
    }
    if (!device_is_ready(fire_led.port)) {
        printk("[%s] LED device not ready\n", TAG);
        return;
    }

    // Init LED
    gpio_pin_configure_dt(&fire_led, GPIO_OUTPUT_INACTIVE);

    // Init knap
    gpio_pin_configure_dt(&fire_button, GPIO_INPUT);
    gpio_pin_interrupt_configure_dt(&fire_button, GPIO_INT_EDGE_TO_ACTIVE);
    gpio_init_callback(&fire_button_cb, fire_button_pressed, BIT(fire_button.pin));
    gpio_add_callback(fire_button.port, &fire_button_cb);

    // Start blink-tråd
    k_thread_create(&fire_thread_data, fire_stack_area,
                    K_THREAD_STACK_SIZEOF(fire_stack_area),
                    fire_thread, NULL, NULL, NULL,
                    5, 0, K_NO_WAIT);

    printk("[%s] Button interrupt configured on pin %d\n", TAG, fire_button.pin);   
}

bool fire_is_active(void) {
    return fire_active;   // din globale variabel
}

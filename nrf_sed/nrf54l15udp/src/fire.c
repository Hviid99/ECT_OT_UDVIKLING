#include "fire.h"
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/printk.h>
#include <string.h>
#include <errno.h>


#define BR_IP6 "fd94:59b5:b7ee:779a:6274:9eaa:9cdd:8073"

// #define BR_IP6 "fd78:ee93:e283:a41:ddd7:96ac:ec48:1884"
#define BR_PORT  54321
#define TAG      "FIRE"

#define BUTTON_NODE DT_ALIAS(sw0)
static const struct gpio_dt_spec fire_button = GPIO_DT_SPEC_GET(BUTTON_NODE, gpios);
static struct gpio_callback fire_button_cb;

static otInstance *g_instance = NULL;

static void fire_button_pressed(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
    printk("[%s] Button pressed – sending FIRE!\n", TAG);

    int sock = zsock_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        printk("[%s] Socket create failed: %d\n", TAG, errno);
        return;
    }

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port   = htons(BR_PORT);
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

void fire_init(otInstance *instance)
{
    g_instance = instance;

    if (!device_is_ready(fire_button.port)) {
        printk("[%s] Button device not ready\n", TAG);
        return;
    }

    gpio_pin_configure_dt(&fire_button, GPIO_INPUT);
    gpio_pin_interrupt_configure_dt(&fire_button, GPIO_INT_EDGE_TO_ACTIVE);
    gpio_init_callback(&fire_button_cb, fire_button_pressed, BIT(fire_button.pin));
    gpio_add_callback(fire_button.port, &fire_button_cb);

    printk("[%s] Button interrupt configured on pin %d\n", TAG, fire_button.pin);
}

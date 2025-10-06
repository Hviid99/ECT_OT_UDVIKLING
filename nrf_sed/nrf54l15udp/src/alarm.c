#include "alarm.h"
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/sys/printk.h>

#define LED_NODE DT_ALIAS(led0)
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(LED_NODE, gpios);

void alarm_init(void)
{
    if (!device_is_ready(led.port)) {
        printk("Alarm LED device not ready\n");
        return;
    }
    gpio_pin_configure_dt(&led, GPIO_OUTPUT_INACTIVE);
    printk("Alarm initialized (LED ready)\n");
}

void alarm_trigger(void)
{
    printk("Alarm triggered - LED on!\n");
    gpio_pin_set_dt(&led, 1);

    // Sluk LED efter 10 sekunder
    k_sleep(K_SECONDS(10));

    gpio_pin_set_dt(&led, 0);
    printk("Alarm ended - LED off\n");
}

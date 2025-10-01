#include "adc.h"
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

/* Du kan evt. lave en global variabel som "simulerer" en måling */
static int dummy_voltage = 3300;  // 3.3V default
static battery_status_t dummy_status = BAT_GREEN;

int battery_init(void)
{
    printk("Dummy ADC init på nRF54L15\n");
    return 0;
}

battery_status_t get_battery_status(void)
{
    /* Du kan evt. skifte status dynamisk baseret på dummy_voltage */
    if (dummy_voltage > 3000) {
        dummy_status = BAT_GREEN;
    } else if (dummy_voltage > 2600) {
        dummy_status = BAT_YELLOW;
    } else {
        dummy_status = BAT_RED;
    }

    return dummy_status;
}

int get_battery_voltage_mv(void)
{
    /* Returnér bare dummy værdien */
    return dummy_voltage;
}

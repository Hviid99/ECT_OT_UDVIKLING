#include <zephyr/kernel.h>
#include <zephyr/net/openthread.h>
#include <openthread/thread.h>
#include "network.h"
#include "adc.h" 
#include "usb_console.h"


void main(void)
{
    otInstance *instance = openthread_get_default_instance();
    configure_thread_network_leader(instance);

    if (battery_init() == 0) {
        printk("Dummy battery ADC ready\n");
    } else {
        printk("Dummy battery ADC init failed!\n");
    }

    udp_listener_start(instance);
}

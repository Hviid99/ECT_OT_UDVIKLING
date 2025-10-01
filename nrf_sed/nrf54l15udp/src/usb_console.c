#include "usb_console.h"
#include <zephyr/kernel.h>

int usb_console_init(void){
#if DT_NODE_HAS_COMPAT(DT_CHOSEN(zephyr_shell_uart), zephyr_cdc_acm_uart)
    int ret;
    const struct device *dev;
    uint32_t dtr = 0U;

    /* Enable USB subsystem */
    ret = usb_enable(NULL);
    if (ret != 0 && ret != -EALREADY) {
        return ret;
    }

    /* Get UART device bound to zephyr,shell-uart */
    dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_shell_uart));
    if (!device_is_ready(dev)) {
        return -ENODEV;
    }

    /* Wait until terminal asserts DTR */
    while (!dtr) {
        ret = uart_line_ctrl_get(dev, UART_LINE_CTRL_DTR, &dtr);
        if (ret) {
            continue;
        }
        k_msleep(100);
    }

    /* Signal to host that we’re ready */
    (void)uart_line_ctrl_set(dev, UART_LINE_CTRL_DCD, 1);
    (void)uart_line_ctrl_set(dev, UART_LINE_CTRL_DSR, 1);
#endif

    return 0;
}

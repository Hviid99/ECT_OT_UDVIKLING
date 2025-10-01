#ifndef USB_CONSOLE_H
#define USB_CONSOLE_H

#include <zephyr/device.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/drivers/uart.h>

int usb_console_init(void);

#endif // USB_CONSOLE_H

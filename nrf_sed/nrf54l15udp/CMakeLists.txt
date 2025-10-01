cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(nrf54l15udp)

target_sources(app PRIVATE src/main.c)
target_sources(app PRIVATE src/adc.c)
target_sources(app PRIVATE src/network.c)
target_sources(app PRIVATE src/udp.c)
target_sources(app PRIVATE src/usb_console.c)

target_include_directories(app PRIVATE include)
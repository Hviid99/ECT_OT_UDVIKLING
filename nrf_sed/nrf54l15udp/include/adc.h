#ifndef ADC_H
#define ADC_H

typedef enum {
    BAT_GREEN,
    BAT_YELLOW,
    BAT_RED,
    BAT_NONE
} battery_status_t;

int battery_init(void);
battery_status_t get_battery_status(void);
int get_battery_voltage_mv(void);

#endif /* ADC_H_ */

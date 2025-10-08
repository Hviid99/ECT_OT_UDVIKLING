#ifndef FIRE_H
#define FIRE_H

#include <openthread/instance.h>
void fire_init(otInstance *instance);

// --- Tilføjet ved manglende funktions kald
void fire_start(void);
void fire_stop(void);
bool fire_is_active(void);

#endif
